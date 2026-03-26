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

// InodeToProcess maps socket inodes to their owning PIDs
// by walking /proc/[pid]/fd/ symlinks
func InodeToProcess() (map[uint64]int, error) {
	inodeMap := make(map[uint64]int)
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", "/proc", err)
	}
	for _, proc := range procs {
		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		fdPath := filepath.Join("/proc", proc.Name(), "fd")
		fds, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if err != nil {
				continue
			}
			if !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inodeStr := link[8 : len(link)-1]
			inode, _ := strconv.ParseUint(inodeStr, 10, 64)
			inodeMap[inode] = pid
		}
	}
	return inodeMap, nil
}
