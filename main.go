package main

import (
	"fmt"
	"github.com/treytuscai/meshwatch/internal/discovery"
	"log"
)

func main() {
	entries, err := discovery.ParseProcNetTCP()
	if err != nil {
		log.Fatal(err)
	}
	inodeMap, err := discovery.InodeToProcess()
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		pid := inodeMap[e.Inode]
		info, err := discovery.GetProcessInfo(pid)
		if err != nil {
			continue
		}
		fmt.Printf("%-21s %-21s %-13s %s\n",
			fmt.Sprintf("%s:%d", e.LocalIP, e.LocalPort),
			fmt.Sprintf("%s:%d", e.RemoteIP, e.RemotePort),
			e.State,
			info.Name,
		)
	}
}
