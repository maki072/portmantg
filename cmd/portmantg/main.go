// Command portmantg runs the Telegram proxy distribution service.
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/maki072/portmantg/internal/api"
	"github.com/maki072/portmantg/internal/db"
	"github.com/maki072/portmantg/internal/firewall"
	"github.com/maki072/portmantg/internal/telemt"

	_ "modernc.org/sqlite"
)

func main() {
	var (
		addr            = flag.String("addr", ":8080", "HTTP listen address")
		dbPath          = flag.String("db", "/var/lib/portmantg/portmantg.db", "SQLite database path")
		webDir          = flag.String("web", "/opt/portmantg/web", "Directory with static web files")
		telemtURL       = flag.String("telemt-url", "http://127.0.0.1:9091", "telemt API base URL")
		targetIP        = flag.String("target-ip", "", "DNAT target IP (MTProxy backend)")
		targetPort      = flag.Int("target-port", 8444, "DNAT target port (MTProxy backend)")
		portStart       = flag.Int("port-start", 1000, "First user port")
		portEnd         = flag.Int("port-end", 3000, "Last user port")
		proxyHost       = flag.String("proxy-host", "", "Public hostname for proxy links")
		sniDomain       = flag.String("sni", "", "SNI domain embedded in TLS secret")
		rateLimit       = flag.Duration("rate-limit", 5*time.Minute, "Cooldown between new proxy requests per device")
		inactiveAge     = flag.Duration("inactive-age", 30*24*time.Hour, "Free port after this duration of inactivity")
		cleanupEvery    = flag.Duration("cleanup-every", 6*time.Hour, "How often to run the inactivity cleanup")
		adminUser       = flag.String("admin-user", "", "HTTP basic auth username for /api/admin (empty = disabled)")
		adminPass       = flag.String("admin-pass", "", "HTTP basic auth password for /api/admin")
		turnstileSecret = flag.String("turnstile-secret", "", "Cloudflare Turnstile secret key (empty = disabled)")
		bruteWindow     = flag.Duration("brute-window", 15*time.Minute, "Brute-force lockout window")
		bruteMaxFails   = flag.Int("brute-max-fails", 10, "Failed attempts before lockout")
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
	mux.Handle("/api/", apiHandler.Routes())

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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runCleanup(ctx, database, tm, fw, *inactiveAge, *cleanupEvery)

	// Start server.
	go func() {
		log.Printf("[main] listening on %s", *addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Wait for signal.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[main] shutting down...")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("[main] shutdown error: %v", err)
	}
	log.Println("[main] stopped")
}

// runCleanup periodically removes inactive users.
func runCleanup(ctx context.Context, database *db.DB, tm *telemt.Client, fw *firewall.Manager, age, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanupInactive(database, tm, fw, age)
		}
	}
}

func cleanupInactive(database *db.DB, tm *telemt.Client, fw *firewall.Manager, age time.Duration) {
	users, err := database.InactiveUsers(age)
	if err != nil {
		log.Printf("[cleanup] InactiveUsers: %v", err)
		return
	}
	for _, u := range users {
		log.Printf("[cleanup] removing inactive user port=%d username=%s last_seen=%s",
			u.Port, u.Username, u.LastSeen.Format(time.RFC3339))
		if err := tm.DeleteUser(u.Username); err != nil {
			log.Printf("[cleanup] telemt.DeleteUser %s: %v", u.Username, err)
		}
		fw.RemovePort(u.Port)
		if err := database.DeleteUser(u.Port); err != nil {
			log.Printf("[cleanup] db.DeleteUser port=%d: %v", u.Port, err)
		}
	}
	if len(users) > 0 {
		log.Printf("[cleanup] removed %d inactive users", len(users))
	}
}