// Command portmantg runs the Telegram proxy distribution service.
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/maki072/portmantg/internal/api"
	"github.com/maki072/portmantg/internal/db"
	"github.com/maki072/portmantg/internal/firewall"
	"github.com/maki072/portmantg/internal/rst"
	"github.com/maki072/portmantg/internal/telemt"

	_ "modernc.org/sqlite"
)

func main() {
	var (
		addr              = flag.String("addr", ":8080", "HTTP listen address")
		dbPath            = flag.String("db", "/var/lib/portmantg/portmantg.db", "SQLite database path")
		webDir            = flag.String("web", "/opt/portmantg/web", "Directory with static web files")
		telemtURL         = flag.String("telemt-url", "http://127.0.0.1:9091", "telemt API base URL")
		targetIP          = flag.String("target-ip", "", "DNAT target IP (MTProxy backend)")
		targetPort        = flag.Int("target-port", 8444, "DNAT target port (MTProxy backend)")
		portStart         = flag.Int("port-start", 1000, "First user port")
		portEnd           = flag.Int("port-end", 3000, "Last user port")
		proxyHost         = flag.String("proxy-host", "", "Public hostname for proxy links")
		sniDomain         = flag.String("sni", "", "SNI domain embedded in TLS secret")
		rateLimit         = flag.Duration("rate-limit", 5*time.Minute, "Cooldown between new proxy requests per device")
		inactiveAge       = flag.Duration("inactive-age", 30*24*time.Hour, "Free port after this duration of inactivity")
		cleanupEvery      = flag.Duration("cleanup-every", 6*time.Hour, "How often to run the inactivity cleanup")
		adminUser         = flag.String("admin-user", "", "HTTP basic auth username for /api/admin (empty = disabled)")
		adminPass         = flag.String("admin-pass", "", "HTTP basic auth password for /api/admin")
		turnstileSecret   = flag.String("turnstile-secret", "", "Cloudflare Turnstile secret key (empty = disabled)")
		bruteWindow       = flag.Duration("brute-window", 15*time.Minute, "Brute-force lockout window")
		bruteMaxFails     = flag.Int("brute-max-fails", 10, "Failed attempts before lockout")
		rstEnable         = flag.Bool("rst-monitor", false, "Enable embedded RST/TSPU monitor")
		rstDBPath         = flag.String("rst-db", "", "RST monitor SQLite DB path (default: same dir as -db)")
	)
	flag.Parse()

	// Open main database.
	database, err := db.Open(*dbPath)
	if err != nil {
		log.Fatalf("open db %s: %v", *dbPath, err)
	}
	defer database.Close()

	// Build clients.
	tm := telemt.New(*telemtURL)
	fw := firewall.New(*targetIP, *targetPort)

	// Build API handler.
	apiCfg := api.Config{
		PortStart:       *portStart,
		PortEnd:         *portEnd,
		SNIDomain:       *sniDomain,
		ProxyHost:       *proxyHost,
		RateLimit:       *rateLimit,
		InactiveAge:     *inactiveAge,
		DeviceCookie:    "device_id",
		AdminUser:       *adminUser,
		AdminPass:       *adminPass,
		TurnstileSecret: *turnstileSecret,
		BruteWindow:     *bruteWindow,
		BruteMaxFails:   *bruteMaxFails,
	}
	apiHandler := api.New(database, tm, fw, apiCfg)

	// Build HTTP mux: API + static files.
	mux := http.NewServeMux()

	// Mount API routes.
	mux.Handle("/api/", apiHandler.Routes())

	// RST monitor (optional).
	done := make(chan struct{})
	if *rstEnable {
		rstPath := *rstDBPath
		if rstPath == "" {
			rstPath = filepath.Join(filepath.Dir(*dbPath), "rst.db")
		}
		rstConn, err := sql.Open("sqlite", rstPath+"?_journal=WAL&_timeout=5000")
		if err != nil {
			log.Fatalf("open rst db %s: %v", rstPath, err)
		}
		rstConn.SetMaxOpenConns(1)
		defer rstConn.Close()

		monitor, err := rst.New(rstConn)
		if err != nil {
			log.Fatalf("rst init: %v", err)
		}

		// Mount RST API routes under /api/rst/ — protected by admin basic auth.
		mux.Handle("/api/rst/", apiHandler.AdminMiddleware(monitor.Routes()))

		monitor.Start(done)
		defer monitor.Cleanup()
		log.Printf("[main] RST monitor enabled, db=%s", rstPath)
	}

	// Serve static web files.
	if *webDir != "" {
		if _, err := os.Stat(*webDir); err == nil {
			mux.Handle("/", http.FileServer(http.Dir(*webDir)))
		} else {
			log.Printf("[main] web dir %s not found, skipping static files", *webDir)
		}
	}

	srv := &http.Server{
		Addr:         *addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start inactivity cleanup goroutine.
	ctx, cancel := context.With