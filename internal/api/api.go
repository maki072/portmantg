// Package api implements the HTTP API for portmantg.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/maki072/portmantg/internal/db"
	"github.com/maki072/portmantg/internal/firewall"
	"github.com/maki072/portmantg/internal/telemt"
)

// Config holds API configuration.
type Config struct {
	PortStart         int
	PortEnd           int
	SNIDomain         string // domain embedded in TLS secret for SNI camouflage
	ProxyHost         string // public hostname used in proxy links
	RateLimit         time.Duration
	InactiveAge       time.Duration
	DeviceCookie      string
	AdminUser         string // HTTP basic auth username for /api/admin (empty = no auth)
	AdminPass         string // HTTP basic auth password for /api/admin
	TurnstileSecret   string // Cloudflare Turnstile secret key (empty = disabled)
	BruteWindow       time.Duration // brute-force window (default 15m)
	BruteMaxFails     int           // max failed admin auth attempts before lockout (default 10)
}

// ── Brute-force limiter ────────────────────────────────────────────────────────

type bruteEntry struct {
	fails   int
	blocked time.Time
	window  time.Time
}

type bruteLimiter struct {
	mu      sync.Mutex
	entries map[string]*bruteEntry
	window  time.Duration
	max     int
}

func newBruteLimiter(window time.Duration, max int) *bruteLimiter {
	if window <= 0 {
		window = 15 * time.Minute
	}
	if max <= 0 {
		max = 10
	}
	return &bruteLimiter{entries: make(map[string]*bruteEntry), window: window, max: max}
}

// Check returns true if ip is blocked.
func (b *bruteLimiter) Check(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[ip]
	if !ok {
		return false
	}
	if !e.blocked.IsZero() && time.Now().Before(e.blocked) {
		return true
	}
	if time.Now().After(e.window) {
		delete(b.entries, ip)
		return false
	}
	return false
}

// Fail records a failed attempt; returns true if now blocked.
func (b *bruteLimiter) Fail(ip string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[ip]
	if !ok || time.Now().After(e.window) {
		e = &bruteEntry{window: time.Now().Add(b.window)}
		b.entries[ip] = e
	}
	e.fails++
	if e.fails >= b.max {
		e.blocked = time.Now().Add(b.window)
		return true
	}
	return false
}

// Success clears fail counter for ip.
func (b *bruteLimiter) Success(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.entries, ip)
}

// Handler is the main HTTP handler.
type Handler struct {
	db         *db.DB
	telemt     *telemt.Client
	firewall   *firewall.Manager
	cfg        Config
	adminBrute *bruteLimiter // brute-force protection for /api/admin
	proxyBrute *bruteLimiter // brute-force protection for /api/proxy (turnstile fails)
}

// New creates a new Handler.
func New(database *db.DB, tm *telemt.Client, fw *firewall.Manager, cfg Config) *Handler {
	return &Handler{
		db:         database,
		telemt:     tm,
		firewall:   fw,
		cfg:        cfg,
		adminBrute: newBruteLimiter(cfg.BruteWindow, cfg.BruteMaxFails),
		proxyBrute: newBruteLimiter(cfg.BruteWindow, cfg.BruteMaxFails),
	}
}

// Routes registers all HTTP routes.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/proxy", h.handleProxy)
	mux.HandleFunc("/api/status", h.handleStatus)
	mux.HandleFunc("/api/admin/users", h.basicAuth(h.handleAdminUsers))
	mux.HandleFunc("/api/admin/delete", h.basicAuth(h.handleAdminDelete))
	return mux
}

// jsonResponse writes a JSON response with the given status code.
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type proxyResponse struct {
	Port    int    `json:"port"`
	Secret  string `json:"secret"`
	Link    string `json:"link"`
	Created bool   `json:"created"` // true if new, false if existing
}

type errorResponse struct {
	Error      string `json:"error"`
	RetryAfter int    `json:"retry_after,omitempty"` // seconds
}

// handleProxy handles GET /api/proxy
// Returns existing proxy for this device, or creates a new one.
func (h *Handler) handleProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	deviceID := h.getOrSetDeviceID(w, r)
	clientIP := realIP(r)

	// Check if device already has a proxy (no captcha needed for returning users).
	user, err := h.db.FindByDeviceID(deviceID)
	if err != nil {
		log.Printf("[api] FindByDeviceID: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if user != nil {
		// Touch last seen and return existing proxy.
		_ = h.db.TouchLastSeen(user.Port, clientIP)
		jsonResponse(w, http.StatusOK, proxyResponse{
			Port:    user.Port,
			Secret:  user.Secret,
			Link:    h.buildLink(user.Port, user.Secret),
			Created: false,
		})
		return
	}

	// Brute-force lockout check.
	if h.proxyBrute.Check(clientIP) {
		jsonResponse(w, http.StatusTooManyRequests, errorResponse{
			Error:      "too many requests, try later",
			RetryAfter: int(h.cfg.BruteWindow.Seconds()),
		})
		return
	}

	// Turnstile captcha verification (only for new proxy creation).
	token := r.URL.Query().Get("cf-turnstile-response")
	if token == "" {
		token = r.Header.Get("X-Turnstile-Response")
	}
	if !h.verifyTurnstile(token, clientIP) {
		h.proxyBrute.Fail(clientIP)
		jsonResponse(w, http.StatusForbidden, errorResponse{Error: "captcha required"})
		return
	}
	h.proxyBrute.Success(clientIP)

	// Rate limit check (only for new proxy requests).
	last, err := h.db.GetRateLimit(deviceID)
	if err != nil {
		log.Printf("[api] GetRateLimit: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if !last.IsZero() && time.Since(last) < h.cfg.RateLimit {
		remaining := int(h.cfg.RateLimit.Seconds() - time.Since(last).Seconds())
		jsonResponse(w, http.StatusTooManyRequests, errorResponse{
			Error:      "rate limited",
			RetryAfter: remaining,
		})
		return
	}

	// Allocate port.
	port, err := h.db.NextFreePort(h.cfg.PortStart, h.cfg.PortEnd)
	if err != nil {
		log.Printf("[api] NextFreePort: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if port == 0 {
		jsonResponse(w, http.StatusServiceUnavailable, errorResponse{Error: "no ports available"})
		return
	}

	// Generate secret.
	secret, err := generateSecret()
	if err != nil {
		log.Printf("[api] generateSecret: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	username := fmt.Sprintf("u%d", port)
	now := time.Now().UTC()
	newUser := &db.User{
		Port:      port,
		Username:  username,
		Secret:    secret,
		DeviceID:  deviceID,
		LastIP:    realIP(r),
		CreatedAt: now,
		LastSeen:  now,
	}

	// Register in telemt.
	if err := h.telemt.CreateUser(username, secret); err != nil {
		log.Printf("[api] telemt.CreateUser port=%d: %v", port, err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "failed to create proxy"})
		return
	}

	// Add iptables rules.
	if err := h.firewall.AddPort(port, username); err != nil {
		log.Pri