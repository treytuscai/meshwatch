// Package discovery provides tools for scanning Linux /proc
// to discover running services and their network connections.
package discovery

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// SockEntry represents a parsed line from /proc/net/tcp.
type SockEntry struct {
	LocalIP    string
	LocalPort  uint64
	RemoteIP   string
	RemotePort uint64
	State      string
	Inode      uint64
}

// tcpStates maps hex state codes from /proc/net/tcp to human-readable names.
var tcpStates = map[string]string{
	"01": "ESTABLISHED",
	"0A": "LISTEN",
	"06": "TIME_WAIT",
	"08": "CLOSE_WAIT",
}

// ParseProcNetTCP reads and parses TCP socket entries from the given /proc path.
func ParseProcNetTCP() ([]SockEntry, error) {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", "/proc/net/tcp", err)
	}
	defer f.Close()

	var entries []SockEntry

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[0] == "sl" {
			continue
		}
		localIP, localPort, _ := parseAddr(fields[1])
		remoteIP, remotePort, _ := parseAddr(fields[2])
		state := parseState(fields[3])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		entry := SockEntry{
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      state,
			Inode:      inode,
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

func hexToIPv4(hex string) string {
	var octets []string
	for i := len(hex); i > 1; i -= 2 {
		b, _ := strconv.ParseUint(hex[i-2:i], 16, 8)
		octets = append(octets, strconv.FormatUint(b, 10))
	}
	return strings.Join(octets, ".")
}

func parseAddr(s string) (string, uint64, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr: %s", s)
	}
	ip := hexToIPv4(parts[0])
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	return ip, port, nil
}

func parseState(hex string) string {
	if s, ok := tcpStates[hex]; ok {
		return s
	}
	return "UNKNOWN"
}
