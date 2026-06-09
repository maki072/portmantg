// Package db manages the SQLite database for portmantg.
package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite connection.
type DB struct {
	conn *sql.DB
}

// User represents a proxy user record.
type User struct {
	Port      int
	Username  string
	Secret    string
	DeviceID  string
	LastIP    string
	CreatedAt time.Time
	LastSeen  time.Time
}

// Open opens (or creates) the SQLite database at the given path.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	d := &DB{conn: conn}
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) migrate() error {
	_, err := d.conn.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			port        INTEGER PRIMARY KEY,
			username    TEXT    NOT NULL UNIQUE,
			secret      TEXT    NOT NULL,
			device_id   TEXT    NOT NULL UNIQUE,
			last_ip     TEXT    NOT NULL DEFAULT '',
			created_at  DATETIME NOT NULL,
			last_seen   DATETIME NOT NULL
		);
		CREATE TABLE IF NOT EXISTS rate_limit (
			device_id    TEXT PRIMARY KEY,
			last_request DATETIME NOT NULL
		);
	`)
	if err != nil {
		return err
	}
	_, _ = d.conn.Exec("ALTER TABLE users ADD COLUMN last_ip TEXT NOT NULL DEFAULT ''")
	return nil
}

// Close closes the database connection.
func (d *DB) Close() error { return d.conn.Close() }

// FindByDeviceID returns user for the given device, or nil if not found.
func (d *DB) FindByDeviceID(deviceID string) (*User, error) {
	u := &User{}
	err := d.conn.QueryRow(
		"SELECT port, username, secret, device_id, last_ip, created_at, last_seen FROM users WHERE device_id = ?",
		deviceID,
	).Scan(&u.Port, &u.Username, &u.Secret, &u.DeviceID, &u.LastIP, &u.CreatedAt, &u.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// FindByPort returns user for the given port, or nil if not found.
func (d *DB) FindByPort(port int) (*User, error) {
	u := &User{}
	err := d.conn.QueryRow(
		"SELECT port, username, secret, device_id, last_ip, created_at, last_seen FROM users WHERE port = ?",
		port,
	).Scan(&u.Port, &u.Username, &u.Secret, &u.DeviceID, &u.LastIP, &u.CreatedAt, &u.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// NextFreePort returns the lowest available port in [start, end], or 0 if none.
func (d *DB) NextFreePort(start, end int) (int, error) {
	rows, err := d.conn.Query("SELECT port FROM users WHERE port BETWEEN ? AND ? ORDER BY port", start, end)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	used := make(map[int]bool)
	for rows.Next() {
		var p int
		if err := rows.Scan(&p); err != nil {
			return 0, err
		}
		used[p] = true
	}
	for p := start; p <= end; p++ {
		if !used[p] {
			return p, nil
		}
	}
	return 0, nil
}

// CreateUser inserts a new user record.
func (d *DB) CreateUser(u *User) error {
	_, err := d.conn.Exec(
		"INSERT INTO users (port, username, secret, device_id, last_ip, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
		u.Port, u.Username, u.Secret, u.DeviceID, u.LastIP, u.CreatedAt, u.LastSeen,
	)
	return err
}

// TouchLastSeen updates last_seen and last_ip for the given port to now.
func (d *DB) TouchLastSeen(port int, ip string) error {
	_, err := d.conn.Exec(
		"UPDATE users SET last_seen = ?, last_ip = ? WHERE port = ?",
		time.Now().UTC(), ip, port,
	)
	return err
}

// DeleteUser removes user by port.
func (d *DB) DeleteUser(port int) error {
	_, err := d.conn.Exec("DELETE FROM users WHERE port = ?", port)
	return err
}

// InactiveUsers returns users whose last_seen is older than the given duration.
func (d *DB) InactiveUsers(olderThan time.Duration) ([]User, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	rows, err := d.conn.Query(
		"SELECT port, username, secret, device_id, last_ip, created_at, last_seen FROM users WHERE last_seen < ?",
		cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Port, &u.Username, &u.Secret, &u.DeviceID, &u.LastIP, &u.CreatedAt, &u.LastSeen); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// GetRateLimit returns the last request time for a device, or zero time if not found.
func (d *DB) GetRateLimit(deviceID string) (time.Time, error) {
	var t time.Time
	err := d.conn.QueryRow("SELECT last_request FROM rate_limit WHERE device_id = ?", deviceID).Scan(&t)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	return t, err
}

// SetRateLimit upserts the last request time for a device.
func (d *DB) SetRateLimit(deviceID string) error {
	_, err := d.conn.Exec(
		"INSERT INTO rate_limit (device_id, last_request) VALUES (?, ?) ON CONFLICT(device_id) DO UPDATE SET last_request = excluded.last_request",
		deviceID, time.Now().UTC(),
	)
	return err
}

// AllUsers returns all users ordered by last_seen desc.
func (d *DB) AllUsers() ([]User, error) {
	rows, err := d.conn.Query(
		"SELECT port, username, secret, device_id, last_ip, created_at, last_seen FROM users ORDER BY last_seen DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Port, &u.Username, &u.Secret, &u.DeviceID, &u.LastIP, &u.CreatedAt, &u.LastSeen); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// CountUsers returns total number of users.
func (d *DB) CountUsers() (int, error) {
	var n int
	err := d.conn.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}