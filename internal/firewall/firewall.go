// Package firewall manages iptables rules for per-user port DNAT.
package firewall

import (
	"fmt"
	"os/exec"
)

// Manager manages iptables DNAT rules for telemt ports.
type Manager struct {
	targetIP   string // MTProxy backend IP
	targetPort int    // MTProxy backend port
}

// New creates a new firewall manager.
func New(targetIP string, targetPort int) *Manager {
	return &Manager{targetIP: targetIP, targetPort: targetPort}
}

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func runIgnoreErr(args ...string) {
	cmd := exec.Command(args[0], args[1:]...)
	_ = cmd.Run()
}

// AddPort adds DNAT + INPUT ACCEPT + SYNACK rate-limit rules for the given port.
func (m *Manager) AddPort(port int, username string) error {
	dest := fmt.Sprintf("%s:%d", m.targetIP, m.targetPort)
	comment := fmt.Sprintf("portmantg: user=%s", username)

	// DNAT in TELEMT_PORTS chain
	if err := run("iptables", "-t", "nat", "-A", "TELEMT_PORTS",
		"-p", "tcp", "--dport", fmt.Sprint(port),
		"-m", "comment", "--comment", comment,
		"-j", "DNAT", "--to-destination", dest,
	); err != nil {
		return fmt.Errorf("add DNAT: %w", err)
	}

	// ACCEPT in TELEMT_INPUT chain
	if err := run("iptables", "-A", "TELEMT_INPUT",
		"-p", "tcp", "--dport", fmt.Sprint(port),
		"-m", "comment", "--comment", comment,
		"-j", "ACCEPT",
	); err != nil {
		// Rollback DNAT
		runIgnoreErr("iptables", "-t", "nat", "-D", "TELEMT_PORTS",
			"-p", "tcp", "--dport", fmt.Sprint(port), "-j", "DNAT", "--to-destination", dest)
		return fmt.Errorf("add INPUT ACCEPT: %w", err)
	}

	// SYN/ACK rate-limit in TELEMT_SYNACK chain
	if err := run("iptables", "-A", "TELEMT_SYNACK",
		"-p", "tcp", "--sport", fmt.Sprint(port),
		"--tcp-flags", "SYN,ACK", "SYN,ACK",
		"-m", "hashlimit",
		"--hashlimit-above", "1/sec",
		"--hashlimit-burst", "1",
		"--hashlimit-mode", "srcip,dstip",
		"--hashlimit-name", fmt.Sprintf("synack_%d", port),
		"-m", "comment", "--comment", comment,
		"-j", "DROP",
	); err != nil {
		// Non-fatal: log but don't rollback
		fmt.Printf("[firewall] WARN: add SYNACK rate-limit for port %d: %v\n", port, err)
	}

	// Persist
	if err := run("netfilter-persistent", "save"); err != nil {
		fmt.Printf("[firewall] WARN: netfilter-persistent save: %v\n", err)
	}

	return nil
}

// RemovePort removes all iptables rules for the given port.
func (m *Manager) RemovePort(port int) {
	dest := fmt.Sprintf("%s:%d", m.targetIP, m.targetPort)

	runIgnoreErr("iptables", "-t", "nat", "-D", "TELEMT_PORTS",
		"-p", "tcp", "--dport", fmt.Sprint(port),
		"-j", "DNAT", "--to-destination", dest)

	runIgnoreErr("iptables", "-D", "TELEMT_INPUT",
		"-p", "tcp", "--dport", fmt.Sprint(port), "-j", "ACCEPT")

	// Remove SYNACK rule (find by comment)
	runIgnoreErr("bash", "-c", fmt.Sprintf(
		`iptables -L TELEMT_SYNACK --line-numbers -n | grep "portmantg: " | grep "spt:%d " | awk '{print $1}' | sort -rn | xargs -r -I{} iptables -D TELEMT_SYNACK {}`,
		port,
	))

	runIgnoreErr("netfilter-persistent", "