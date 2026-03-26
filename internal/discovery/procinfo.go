// Package discovery provides tools for scanning Linux /proc
// to discover running services and their network connections.
package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessInfo holds metadata about a running process.
type ProcessInfo struct {
	Name    string // from /proc/[pid]/comm
	Cmdline string // from /proc/[pid]/cmdline
}

func GetProcessInfo(pid int) (*ProcessInfo, error) {
	name, err := readProcFile(pid, "comm")
	if err != nil {
		return nil, err
	}
	cmdline, err := readProcFile(pid, "cmdline")
	if err != nil {
		return nil, err
	}
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
	return &ProcessInfo{Name: name, Cmdline: cmdline}, nil
}

func readProcFile(pid int, filename string) (string, error) {
	path := filepath.Join("/proc", strconv.Itoa(pid), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	return strings.TrimSpace(string(data)), nil
}
