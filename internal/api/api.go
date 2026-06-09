// Package api implements the HTTP API for portmantg.
package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/maki072/portmantg/internal/db"
	"github.com/maki072/portmantg/internal/firewall"
	"github.com/maki072/portmantg/internal/telemt"
)

// Config holds API configuration.
type Config struct {
	PortStart    int
	PortEnd      int
	SNIDomain    string // domain embedded in TLS secret (e.g. "ad.2vp.in")
	ProxyHost    string // public hostname for proxy links (e.g. "t.2vp.in")
	RateLimit    time.Duration
	InactiveAge  time.Duration
	DeviceCookie string
}

// Handler is the main HTTP handler.
type Handler struct {
	db       *db.DB
	telemt   *telemt.Client
	firewall *firewall.Manager
	cfg      Config
}

// New creates a new Handler.
func New(database *db.DB, tm *telemt.Client, fw *firewall.Manager, cfg Config) *Handler {
	return &Handler{
		db:       database,
		telemt:   tm,
		firewall: fw,
		cfg:      cfg,
	}
}

// Routes registers all HTTP routes.
func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/proxy", h.handleProxy)
	mux.HandleFunc("/api/status", h.handleStatus)
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

	// Check if device already has a proxy.
	user, err := h.db.FindByDeviceID(deviceID)
	if err != nil {
		log.Printf("[api] FindByDeviceID: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if user != nil {
		// Touch last seen and return existing proxy.
		_ = h.db.TouchLastSeen(user.Port)
		jsonResponse(w, http.StatusOK, proxyResponse{
			Port:    user.Port,
			Secret:  user.Secret,
			Link:    h.buildLink(user.Port, user.Secret),
			Created: false,
		})
		return
	}

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
		log.Printf("[api] firewall.AddPort port=%d: %v", port, err)
		// Attempt telemt rollback.
		_ = h.telemt.DeleteUser(username)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "failed to configure firewall"})
		return
	}

	// Save to DB.
	if err := h.db.CreateUser(newUser); err != nil {
		log.Printf("[api] CreateUser port=%d: %v", port, err)
		// Rollback telemt + firewall.
		_ = h.telemt.DeleteUser(username)
		h.firewall.RemovePort(port)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}

	// Update rate limit.
	_ = h.db.SetRateLimit(deviceID)

	log.Printf("[api] created proxy port=%d username=%s device=%s", port, username, deviceID)

	jsonResponse(w, http.StatusCreated, proxyResponse{
		Port:    port,
		Secret:  secret,
		Link:    h.buildLink(port, secret),
		Created: true,
	})
}

type statusResponse struct {
	HasProxy bool   `json:"has_proxy"`
	Port     int    `json:"port,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Link     string `json:"link,omitempty"`
}

// handleStatus handles GET /api/status
// Returns proxy info for this device without side effects.
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, errorResponse{Error: "method not allowed"})
		return
	}

	deviceID := h.getOrSetDeviceID(w, r)
	user, err := h.db.FindByDeviceID(deviceID)
	if err != nil {
		log.Printf("[api] status FindByDeviceID: %v", err)
		jsonResponse(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
		return
	}
	if user == nil {
		jsonResponse(w, http.StatusOK, statusResponse{HasProxy: false})
		return
	}
	jsonResponse(w, http.StatusOK, statusResponse{
		HasProxy: true,
		Port:     user.Port,
		Secret:   user.Secret,
		Link:     h.buildLink(user.Port, user.Secret),
	})
}

// getOrSetDeviceID returns existing device_id cookie, or sets a new one.
func (h *Handler) getOrSetDeviceID(w http.ResponseWriter, r *http.Request) string {
	c, err := r.Cookie(h.cfg.DeviceCookie)
	if err == nil && c.Value != "" {
		return c.Value
	}
	id := generateDeviceID()
	http.SetCookie(w, &http.Cookie{
		Name:     h.cfg.DeviceCookie,
		Value:    id,
		HttpOnly: true,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60, // 1 year
		SameSite: http.SameSiteLaxMode,
	})
	return id
}

// buildLink builds a tg://proxy link with TLS secret (ee + secret + hex(sni)).
func (h *Handler) buildLink(port int, secret string) string {
	sniHex := hex.EncodeToString([]byte(h.cfg.SNIDomain))
	tlsSecret := "ee" + secret + sniHex
	return fmt.Sprintf("tg://proxy?server=%s&port=%d&secret=%s",
		h.cfg.ProxyHost, port, tlsSecret)
}

// generateSecret returns a random 32-hex-char secret.
func generateSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateDeviceID returns a random UUID-like string.
func generateDeviceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
