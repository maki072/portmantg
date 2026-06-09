// Package rst embeds the RST/TSPU monitor (originally rst-monitor).
// It collects RST+ACK packets on port 443 via iptables LOG rules,
// stores them in SQLite, and exposes an HTTP API for the admin panel.
package rst

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// ── Constants ─────────────────────────────────────────────────────────────────

const (
	LogPrefix      = "PANVEX_RST"
	MonPort        = "443"
	GitHubCIDRURL  = "https://raw.githubusercontent.com/tread-lightly/CyberOK_Skipa_ips/main/lists/skipa_cidr.txt"
	GptruAPIURL    = "https://stats.gptru.pro:4443/rst/collect.php"
	GptruToken     = "upe4d_rst_2026"
	SyncInterval   = 12 * time.Hour
	SubmitInterval = 30 * time.Minute
	CollectTick    = 30 * time.Second
)

// whitelistRE — skip Telegram DCs, RFC-1918, loopback
var whitelistRE = regexp.MustCompile(
	`^(149\.154\.|91\.108\.|91\.105\.|95\.161\.|` +
		`127\.|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|` +
		`95\.81\.123\.)`,
)

var srcRE = regexp.MustCompile(`SRC=([\d.]+)`)

// ── Config ─────────────────────────────────────────────────────────────────────

type Config struct {
	AutoBlockRST  bool   `json:"auto_block_rst"`
	AutoBlockTSPU bool   `json:"auto_block_tspu"`
	SubmitGptru   bool   `json:"submit_gptru"`
	IpsetRST      string `json:"ipset_rst"`
	IpsetTSPU     string `json:"ipset_tspu"`
}

func defaultConfig() Config {
	return Config{IpsetRST: "rst_block", IpsetTSPU: "tspu_block"}
}

// ── DB ─────────────────────────────────────────────────────────────────────────

func InitDB(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rst_events (
			ip         TEXT    NOT NULL PRIMARY KEY,
			first_seen INTEGER NOT NULL,
			last_seen  INTEGER NOT NULL,
			hit_count  INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS rst_log (
			id      INTEGER PRIMARY KEY AUTOINCREMENT,
			ip      TEXT    NOT NULL,
			seen_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_rst_log_seen ON rst_log(seen_at);
		CREATE TABLE IF NOT EXISTS trusted_ips (
			ip       TEXT    NOT NULL PRIMARY KEY,
			added_at INTEGER NOT NULL,
			note     TEXT    NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS github_ips (
			cidr      TEXT    NOT NULL PRIMARY KEY,
			synced_at INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS rst_config (
			key   TEXT NOT NULL PRIMARY KEY,
			value TEXT NOT NULL DEFAULT ''
		);
	`)
	return err
}

func LoadConfig(db *sql.DB) Config {
	cfg := defaultConfig()
	rows, err := db.Query(`SELECT key, value FROM rst_config`)
	if err != nil {
		return cfg
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		switch k {
		case "auto_block_rst":
			cfg.AutoBlockRST = v == "1"
		case "auto_block_tspu":
			cfg.AutoBlockTSPU = v == "1"
		case "submit_gptru":
			cfg.SubmitGptru = v == "1"
		case "ipset_rst":
			if v != "" {
				cfg.IpsetRST = v
			}
		case "ipset_tspu":
			if v != "" {
				cfg.IpsetTSPU = v
			}
		}
	}
	return cfg
}

func SaveConfig(db *sql.DB, cfg Config) error {
	b2s := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	pairs := [][2]string{
		{"auto_block_rst", b2s(cfg.AutoBlockRST)},
		{"auto_block_tspu", b2s(cfg.AutoBlockTSPU)},
		{"submit_gptru", b2s(cfg.SubmitGptru)},
		{"ipset_rst", cfg.IpsetRST},
		{"ipset_tspu", cfg.IpsetTSPU},
	}
	for _, p := range pairs {
		if _, err := db.Exec(
			`INSERT INTO rst_config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			p[0], p[1],
		); err != nil {
			return err
		}
	}
	return nil
}

// ── ipset / iptables ───────────────────────────────────────────────────────────

func runCmd(args ...string) error {
	return exec.Command(args[0], args[1:]...).Run()
}

func IpsetCreate(name, typ string) { _ = runCmd("ipset", "create", name, typ, "-exist") }
func IpsetAdd(name, cidr string)   { _ = runCmd("ipset", "add", name, cidr, "-exist") }
func IpsetDel(name, cidr string)   { _ = runCmd("ipset", "del", name, cidr, "-exist") }
func IpsetFlush(name string)       { _ = runCmd("ipset", "flush", name) }

func iptRule(name string) []string {
	return []string{"-p", "tcp", "--dport", "443", "-m", "set", "--match-set", name, "src", "-j", "DROP"}
}

func IptExists(name string) bool {
	args := append([]string{"iptables", "-C", "INPUT"}, iptRule(name)...)
	return exec.Command(args[0], args[1:]...).Run() == nil
}

func IptAdd(name string) {
	if !IptExists(name) {
		args := append([]string{"iptables", "-I", "INPUT", "1"}, iptRule(name)...)
		_ = runCmd(args...)
	}
}

func IptDel(name string) {
	for IptExists(name) {
		args := append([]string{"iptables", "-D", "INPUT"}, iptRule(name)...)
		if runCmd(args...) != nil {
			break
		}
	}
}

type BlockStatus struct {
	RuleActive  bool   `json:"rule_active"`
	IpsetExists bool   `json:"ipset_exists"`
	IpsetCount  int    `json:"ipset_count"`
	IpsetName   string `json:"ipset_name"`
}

func GetBlockStatus(ipsetName string) BlockStatus {
	out, err := exec.Command("ipset", "list", ipsetName, "-t").Output()
	exists := err == nil
	count := 0
	if exists {
		re := regexp.MustCompile(`Number of entries:\s*(\d+)`)
		if m := re.FindSubmatch(out); m != nil {
			fmt.Sscanf(string(m[1]), "%d", &count)
		}
	}
	return BlockStatus{
		RuleActive:  IptExists(ipsetName),
		IpsetExists: exists,
		IpsetCount:  count,
		IpsetName:   ipsetName,
	}
}

// ── Whois cache ────────────────────────────────────────────────────────────────

type WhoisEntry struct {
	Org     string `json:"org"`
	ASN     string `json:"asn"`
	Country string `json:"country"`
}

var (
	whoisCache   = map[string]WhoisEntry{}
	whoisCacheMu sync.Mutex
)

func WhoisIP(ip string) WhoisEntry {
	whoisCacheMu.Lock()
	if e, ok := whoisCache[ip]; ok {
		whoisCacheMu.Unlock()
		return e
	}
	whoisCacheMu.Unlock()

	var entry WhoisEntry
	cl := &http.Client{Timeout: 5 * time.Second}
	resp, err := cl.Get("http://ip-api.com/json/" + ip + "?fields=status,org,as,country")
	if err == nil {
		defer resp.Body.Close()
		var d struct {
			Status  string `json:"status"`
			Org     string `json:"org"`
			AS      string `json:"as"`
			Country string `json:"country"`
		}
		if json.NewDecoder(resp.Body).Decode(&d) == nil && d.Status == "success" {
			entry = WhoisEntry{Org: d.Org, ASN: d.AS, Country: d.Country}
		}
	}

	whoisCacheMu.Lock()
	if len(whoisCache) > 512 {
		whoisCache = map[string]WhoisEntry{}
	}
	whoisCache[ip] = entry
	whoisCacheMu.Unlock()
	return entry
}

// ── Collector ──────────────────────────────────────────────────────────────────

func AddCollectRule() {
	check := exec.Command("iptables", "-C", "INPUT",
		"-p", "tcp", "--tcp-flags", "RST,ACK", "RST,ACK",
		"--dport", MonPort,
		"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "4",
	)
	if check.Run() != nil {
		_ = runCmd("iptables", "-I", "INPUT", "1",
			"-p", "tcp", "--tcp-flags", "RST,ACK", "RST,ACK",
			"--dport", MonPort,
			"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "4",
		)
		log.Printf("[rst] iptables LOG rule added (port %s)", MonPort)
	}
}

func RemoveCollectRule() {
	_ = runCmd("iptables", "-D", "INPUT",
		"-p", "tcp", "--tcp-flags", "RST,ACK", "RST,ACK",
		"--dport", MonPort,
		"-j", "LOG", "--log-prefix", LogPrefix+": ", "--log-level", "4",
	)
}

func ReadDmesgIPs() []string {
	out, err := exec.Command("dmesg", "--read-clear", "--level", "warn,notice,info").Output()
	if err != nil {
		return nil
	}
	var ips []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, LogPrefix) {
			continue
		}
		if m := srcRE.FindStringSubmatch(line); m != nil {
			ip := m[1]
			if !whitelistRE.MatchString(ip) {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

func StoreIPs(db *sql.DB, ips []string) map[string]bool {
	seen := map[string]bool{}
	if len(ips) == 0 {
		return seen
	}
	now := time.Now().Unix()
	for _, ip := range ips {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		db.Exec(`INSERT INTO rst_events(ip,first_seen,last_seen,hit_count) VALUES(?,?,?,1)
			ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen, hit_count=hit_count+1`,
			ip, now, now)
		db.Exec(`INSERT INTO rst_log(ip,seen_at) VALUES(?,?)`, ip, now)
	}
	return seen
}

// ── GitHub sync ────────────────────────────────────────────────────────────────

func SyncGitHub(db *sql.DB, cfg Config) (int, error) {
	resp, err := http.Get(GitHubCIDRURL)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err == nil {
			cidrs = append(cidrs, line)
		} else if net.ParseIP(line) != nil {
			cidrs = append(cidrs, line+"/32")
		}
	}

	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	tx.Exec(`DELETE FROM github_ips`)
	for _, cidr := range cidrs {
		tx.Exec(`INSERT OR REPLACE INTO github_ips(cidr,synced_at) VALUES(?,?)`, cidr, now)
	}
	if err := tx.Commit(); err != nil {
		tx.Rollback()
		return 0, err
	}

	if cfg.AutoBlockTSPU {
		IpsetCreate(cfg.IpsetTSPU, "hash:net")
		IpsetFlush(cfg.IpsetTSPU)
		for _, cidr := range cidrs {
			IpsetAdd(cfg.IpsetTSPU, cidr)
		}
		IptAdd(cfg.IpsetTSPU)
	}

	log.Printf("[rst] github: synced %d CIDRs", len(cidrs))
	return len(cidrs), nil
}

// ── gptru submission ───────────────────────────────────────────────────────────

func SubmitGptru(db *sql.DB) (int, error) {
	since := time.Now().Add(-SubmitInterval).Unix()
	rows, err := db.Query(`SELECT DISTINCT ip FROM rst_log WHERE seen_at > ?`, since)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return 0, nil
	}

	body, _ := json.Marshal(map[string]any{"ips": ips, "token": GptruToken})
	cl := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := cl.Post(GptruAPIURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	log.Printf("[rst] gptru: submitted %d IPs", len(ips))
	return len(ips), nil
}

// ── Monitor (long-running goroutines) ─────────────────────────────────────────

// Monitor holds shared state for the RST monitor subsystem.
type Monitor struct {
	db  *sql.DB
	mu  sync.RWMutex
	cfg Config
}

// New creates a Monitor and initialises the database schema.
func New(db *sql.DB) (*Monitor, error) {
	if err := InitDB(db); err != nil {
		return nil, err
	}
	return &Monitor{db: db, cfg: LoadConfig(db)}, nil
}

// GetConfig returns the current config (thread-safe).
func (m *Monitor) GetConfig() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// SetConfig saves and applies new config.
func (m *Monitor) SetConfig(cfg Config) error {
	if err := SaveConfig(m.db, cfg); err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = cfg
	m.mu.Unlock()
	return nil
}

// Start launches background goroutines; returns when ctx is done.
func (m *Monitor) Start(done <-chan struct{}) {
	AddCollectRule()
	go m.runCollector(done)
	go m.runGitHubSync(done)
	go m.runGptruSubmit(done)
}

// Cleanup removes iptables rules added by Start.
func (m *Monitor) Cleanup() { RemoveCollectRule() }

func (m *Monitor) runCollector(done <-chan struct{}) {
	ticker := time.NewTicker(CollectTick)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			ips := ReadDmesgIPs()
			if len(ips) == 0 {
				continue
			}
			unique := StoreIPs(m.db, ips)
			log.Printf("[rst] collector: %d RST packets, %d unique IPs", len(ips), len(unique))
			m.mu.RLock()
			cfg := m.cfg
			m.mu.RUnlock()
			if cfg.AutoBlockRST {
				for ip := range unique {
					IpsetAdd(cfg.IpsetRST, ip)
				}
			}
		}
	}
}

func (m *Monitor) runGitHubSync(done <-chan struct{}) {
	cfg := m.GetConfig()
	if _, err := SyncGitHub(m.db, cfg); err != nil {
		log.Printf("[rst] github: initial sync error: %v", err)
	}
	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if _, err := SyncGitHub(m.db, m.GetConfig()); err != nil {
				log.Printf("[rst] github: sync error: %v", err)
			}
		}
	}
}

func (m *Monitor) runGptruSubmit(done <-chan struct{}) {
	ticker := time.NewTicker(SubmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if !m.GetConfig().SubmitGptru {
				continue
			}
			if _, err := SubmitGptru(m.db); err != nil {
				log.Printf("[rst] gptru: error: %v", err)
			}
		}
	}
}

// ── HTTP handlers ──────────────────────────────────────────────────────────────

// Routes returns an http.Handler for /api/rst/* endpoints.
// Caller is responsible for mounting it and applying auth middleware.
func (m *Monitor) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/rst/stats", m.handleStats)
	mux.HandleFunc("/api/rst/events", m.handleEvents)
	mux.HandleFunc("/api/rst/trusted", m.handleTrusted)
	mux.HandleFunc("/api/rst/github", m.handleGitHub)
	mux.HandleFunc("/api/rst/config", m.handleConfig)
	mux.HandleFunc("/api/rst/block/rst", m.handleBlockRST)
	mux.HandleFunc("/api/rst/block/tspu", m.handleBlockTSPU)
	mux.HandleFunc("/api/rst/github/sync", m.handleGitHubSync)
	mux.HandleFunc("/api/rst/submit", m.handleSubmit)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func (m *Monitor) handleStats(w http.ResponseWriter, r *http.Request) {
	now := time.Now().Unix()
	var unique, total, l24, l1h, trusted, githubCount, topHits int
	var topIP string

	m.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(hit_count),0) FROM rst_events`).Scan(&unique, &total)
	m.db.QueryRow(`SELECT COUNT(DISTINCT ip) FROM rst_log WHERE seen_at > ?`, now-86400).Scan(&l24)
	m.db.QueryRow(`SELECT COUNT(DISTINCT ip) FROM rst_log WHERE seen_at > ?`, now-3600).Scan(&l1h)
	m.db.QueryRow(`SELECT COUNT(*) FROM trusted_ips`).Scan(&trusted)
	m.db.QueryRow(`SELECT COUNT(*) FROM github_ips`).Scan(&githubCount)
	m.db.QueryRow(`SELECT ip, hit_count FROM rst_events ORDER BY hit_count DESC LIMIT 1`).Scan(&topIP, &topHits)

	cfg := m.GetConfig()
	writeJSON(w, 200, map[string]any{
		"unique_ips":   unique,
		"total_hits":   total,
		"last_24h":     l24,
		"last_1h":      l1h,
		"trusted_ips":  trusted,
		"github_cidrs": githubCount,
		"top_ip":       topIP,
		"top_ip_hits":  topHits,
		"block_rst":    GetBlockStatus(cfg.IpsetRST),
		"block_tspu":   GetBlockStatus(cfg.IpsetTSPU),
	})
}

func (m *Monitor) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		var req struct {
			IP string `json:"ip"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if net.ParseIP(req.IP) == nil {
			writeJSON(w, 400, map[string]string{"error": "invalid ip"})
			return
		}
		m.db.Exec(`DELETE FROM rst_events WHERE ip=?`, req.IP)
		m.db.Exec(`DELETE FROM rst_log WHERE ip=?`, req.IP)
		cfg := m.GetConfig()
		IpsetDel(cfg.IpsetRST, req.IP)
		writeJSON(w, 200, map[string]bool{"ok": true})
		return
	}

	search := r.URL.Query().Get("search")
	var (
		rows *sql.Rows
		err  error
	)
	if search != "" {
		rows, err = m.db.Query(
			`SELECT ip,first_seen,last_seen,hit_count FROM rst_events WHERE ip LIKE ? ORDER BY hit_count DESC LIMIT 500`,
			"%"+search+"%",
		)
	} else {
		rows, err = m.db.Query(
			`SELECT ip,first_seen,last_seen,hit_count FROM rst_events ORDER BY hit_count DESC LIMIT 500`,
		)
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type Event struct {
		IP        string `json:"ip"`
		FirstSeen int64  `json:"first_seen"`
		LastSeen  int64  `json:"last_seen"`
		HitCount  int    `json:"hit_count"`
		Org       string `json:"org"`
		ASN       string `json:"asn"`
		Country   string `json:"country"`
		Trusted   bool   `json:"trusted"`
	}

	var events []Event
	for rows.Next() {
		var e Event
		rows.Scan(&e.IP, &e.FirstSeen, &e.LastSeen, &e.HitCount)
		events = append(events, e)
	}
	for i := range events {
		if i >= 200 {
			break
		}
		wi := WhoisIP(events[i].IP)
		events[i].Org = wi.Org
		events[i].ASN = wi.ASN
		events[i].Country = wi.Country
		var n int
		m.db.QueryRow(`SELECT COUNT(*) FROM trusted_ips WHERE ip=?`, events[i].IP).Scan(&n)
		events[i].Trusted = n > 0
	}
	if events == nil {
		events = []Event{}
	}
	writeJSON(w, 200, events)
}

func (m *Monitor) handleTrusted(w http.ResponseWriter, r *http.Request) {
	type Entry struct {
		IP      string `json:"ip"`
		AddedAt int64  `json:"added_at"`
		Note    string `json:"note"`
	}
	switch r.Method {
	case http.MethodGet:
		rows, _ := m.db.Query(`SELECT ip,added_at,note FROM trusted_ips ORDER BY added_at DESC`)
		defer rows.Close()
		var list []Entry
		for rows.Next() {
			var e Entry
			rows.Scan(&e.IP, &e.AddedAt, &e.Note)
			list = append(list, e)
		}
		if list == nil {
			list = []Entry{}
		}
		writeJSON(w, 200, list)
	case http.MethodPost:
		var req struct {
			IP   string `json:"ip"`
			Note string `json:"note"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if net.ParseIP(req.IP) == nil {
			writeJSON(w, 400, map[string]string{"error": "invalid ip"})
			return
		}
		if len(req.Note) > 200 {
			req.Note = req.Note[:200]
		}
		m.db.Exec(`INSERT OR REPLACE INTO trusted_ips(ip,added_at,note) VALUES(?,?,?)`,
			req.IP, time.Now().Unix(), req.Note)
		writeJSON(w, 200, map[string]bool{"ok": true})
	case http.MethodDelete:
		var req struct{ IP string `json:"ip"` }
		json.NewDecoder(r.Body).Decode(&req)
		m.db.Exec(`DELETE FROM trusted_ips WHERE ip=?`, req.IP)
		writeJSON(w, 200, map[string]bool{"ok": true})
	}
}

func (m *Monitor) handleGitHub(w http.ResponseWriter, r *http.Request) {
	ipRows, _ := m.db.Query(`SELECT ip, hit_count, last_seen FROM rst_events`)
	type ipInfo struct {
		hits     int
		lastSeen int64
	}
	caught := map[string]ipInfo{}
	if ipRows != nil {
		defer ipRows.Close()
		for ipRows.Next() {
			var ip string
			var hits int
			var lastSeen int64
			ipRows.Scan(&ip, &hits, &lastSeen)
			caught[ip] = ipInfo{hits: hits, lastSeen: lastSeen}
		}
	}
	cidrRows, _ := m.db.Query(`SELECT cidr, synced_at FROM github_ips ORDER BY cidr LIMIT 2000`)
	if cidrRows != nil {
		defer cidrRows.Close()
	}
	type Entry struct {
		CIDR      string   `json:"cidr"`
		SyncedAt  int64    `json:"synced_at"`
		Caught    bool     `json:"caught"`
		HitCount  int      `json:"hit_count"`
		LastSeen  int64    `json:"last_seen"`
		MatchedIP []string `json:"matched_ips"`
	}
	var list []Entry
	if cidrRows != nil {
		for cidrRows.Next() {
			var e Entry
			cidrRows.Scan(&e.CIDR, &e.SyncedAt)
			_, ipNet, err := net.ParseCIDR(e.CIDR)
			if err == nil {
				for ip, info := range caught {
					if ipNet.Contains(net.ParseIP(ip)) {
						e.Caught = true
						e.HitCount += info.hits
						if info.lastSeen > e.LastSeen {
							e.LastSeen = info.lastSeen
						}
						e.MatchedIP = append(e.MatchedIP, ip)
					}
				}
			}
			list = append(list, e)
		}
	}
	if list == nil {
		list = []Entry{}
	}
	writeJSON(w, 200, list)
}

func (m *Monitor) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var req Config
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad json"})
			return
		}
		if req.IpsetRST == "" {
			req.IpsetRST = "rst_block"
		}
		if req.IpsetTSPU == "" {
			req.IpsetTSPU = "tspu_block"
		}
		if err := m.SetConfig(req); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
	}
	writeJSON(w, 200, m.GetConfig())
}

func (m *Monitor) handleBlockRST(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct{ Enable bool `json:"enable"` }
	json.NewDecoder(r.Body).Decode(&req)
	m.mu.Lock()
	m.cfg.AutoBlockRST = req.Enable
	cfg := m.cfg
	m.mu.Unlock()
	SaveConfig(m.db, cfg)
	if req.Enable {
		IpsetCreate(cfg.IpsetRST, "hash:ip")
		rows, _ := m.db.Query(`SELECT ip FROM rst_events`)
		defer rows.Close()
		for rows.Next() {
			var ip string
			rows.Scan(&ip)
			IpsetAdd(cfg.IpsetRST, ip)
		}
		IptAdd(cfg.IpsetRST)
	} else {
		IptDel(cfg.IpsetRST)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "block_rst": GetBlockStatus(cfg.IpsetRST)})
}

func (m *Monitor) handleBlockTSPU(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req struct{ Enable bool `json:"enable"` }
	json.NewDecoder(r.Body).Decode(&req)
	m.mu.Lock()
	m.cfg.AutoBlockTSPU = req.Enable
	cfg := m.cfg
	m.mu.Unlock()
	SaveConfig(m.db, cfg)
	if req.Enable {
		IpsetCreate(cfg.IpsetTSPU, "hash:net")
		rows, _ := m.db.Query(`SELECT cidr FROM github_ips`)
		defer rows.Close()
		for rows.Next() {
			var cidr string
			rows.Scan(&cidr)
			IpsetAdd(cfg.IpsetTSPU, cidr)
		}
		IptAdd(cfg.IpsetTSPU)
	} else {
		IptDel(cfg.IpsetTSPU)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "block_tspu": GetBlockStatus(cfg.IpsetTSPU)})
}

func (m *Monitor) handleGitHubSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	n, err := SyncGitHub(m.db, m.GetConfig())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "synced": n})
}

func (m *Monitor) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	n, err := SubmitGptru(m.db)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "submitted": n})
}
