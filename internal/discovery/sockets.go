// Package discovery provides tools for scanning Linux /proc
// to discover running services and their network connections.
package discovery

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"net"
	"os"
	"strconv"
	"strings"
)

// SockEntry represents a parsed line from /proc/net/tcp.
type SockEntry struct {
	LocalIP    string
	LocalPort  uint16
	RemoteIP   string
	RemotePort uint16
	State      string
	Inode      uint64
	Protocol   Protocol
}

// TCPState maps the hex state value from /proc/net/tcp to a human-readable name.
var TCPState = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// ParseProcNetTCP reads and parses /proc/net/tcp or /proc/net/tcp6.
func ParseProcNetTCP(path string, proto Protocol) ([]SockEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var entries []SockEntry
	scanner := bufio.NewScanner(f)

	// Skip the header line
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		entry, err := parseTCPLine(line, proto)
		if err != nil {
			continue // Skip malformed lines
		}
		entries = append(entries, entry)
	}
	return entries, scanner.Err()
}

// parseTCPLine parses a single line from /proc/net/tcp.
func parseTCPLine(line string, proto Protocol) (SockEntry, error) {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return SockEntry{}, fmt.Errorf("not enough fields: %d", len(fields))
	}

	localIP, localPort, err := parseAddr(fields[1], proto)
	if err != nil {
		return SockEntry{}, fmt.Errorf("parse local addr: %w", err)
	}
	remoteIP, remotePort, err := parseAddr(fields[2], proto)
	if err != nil {
		return SockEntry{}, fmt.Errorf("parse remote addr: %w", err)
	}

	stateHex := strings.ToUpper(fields[3])
	state, ok := TCPState[stateHex]
	if !ok {
		state = "UNKNOWN"
	}

	inode, _ := strconv.ParseUint(fields[9], 10, 64)

	return SockEntry{
		LocalIP:    localIP,
		LocalPort:  localPort,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		State:      state,
		Inode:      inode,
	}, nil
}

// parseAddr converts a hex-encoded address:port from /proc/net/tcp.
func parseAddr(s string, proto Protocol) (string, uint16, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid addr format: %s", s)
	}

	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}

	ip, err := hexToIP(parts[0], proto)
	if err != nil {
		return "", 0, fmt.Errorf("parse ip: %w", err)
	}

	return ip, uint16(port), nil
}

// hexToIP converts the hex-encoded IP from /proc/net/tcp.
func hexToIP(h string, proto Protocol) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}

	if proto == ProtoTCP && len(b) == 4 {
		// IPv4: stored as a single little-endian 32-bit word
		ip := net.IPv4(b[3], b[2], b[1], b[0])
		return ip.String(), nil
	}

	if proto == ProtoTCP6 && len(b) == 16 {
		// IPv6: stored as four little-endian 32-bit words
		for i := 0; i < 16; i += 4 {
			b[i], b[i+3] = b[i+3], b[i]
			b[i+1], b[i+2] = b[i+2], b[i+1]
		}
		ip := net.IP(b)
		return ip.String(), nil
	}

	return "", fmt.Errorf("unexpected addr length %d for %s", len(b), proto)
}

// InodeToProcess maps socket inodes to PIDs by walking /proc/[pid]/fd/.
func InodeToProcess() (map[uint64]int, error) {
	inodeMap := make(map[uint64]int)

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("readdir /proc: %w", err)
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue // Not a PID directory
		}

		fdPath := filepath.Join("/proc", proc.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue // Permission denied or process exited
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil {
				continue
			}
			// Socket links look like "socket:[12345]"
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := link[8 : len(link)-1]
			inode, err := strconv.ParseUint(inodeStr, 10, 64)
			if err != nil {
				continue
			}
			inodeMap[inode] = pid
		}
	}
	return inodeMap, nil
}

// ProcessInfo reads the command name and full cmdline for a PID.
type ProcessInfo struct {
	PID     int
	Name    string // from /proc/[pid]/comm
	Cmdline string // from /proc/[pid]/cmdline
}

// GetProcessInfo reads process metadata from /proc.
func GetProcessInfo(pid int) ProcessInfo {
	info := ProcessInfo{PID: pid}

	// Read short name from /proc/[pid]/comm
	commPath := filepath.Join("/proc", strconv.Itoa(pid), "comm")
	if data, err := os.ReadFile(commPath); err == nil {
		info.Name = strings.TrimSpace(string(data))
	} else {
		info.Name = fmt.Sprintf("pid-%d", pid)
	}

	// Read full command line from /proc/[pid]/cmdline (null-separated)
	cmdlinePath := filepath.Join("/proc", strconv.Itoa(pid), "cmdline")
	if data, err := os.ReadFile(cmdlinePath); err == nil {
		info.Cmdline = strings.ReplaceAll(strings.TrimRight(string(data), "\x00"), "\x00", " ")
	}

	return info
}