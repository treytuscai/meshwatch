package main

import (
	"github.com/treytuscai/meshwatch/internal/discovery"
	"log"
	"fmt"
)

func main() {
	entries, err := discovery.ParseProcNetTCP()
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		fmt.Printf("%-21s %-21s %-13s Inode:%d\n",
			fmt.Sprintf("%s:%d", e.LocalIP, e.LocalPort),
			fmt.Sprintf("%s:%d", e.RemoteIP, e.RemotePort),
			e.State,
			e.Inode,
		)
	}
	inodeMap, _ := discovery.InodeToProcess()
	for _, e := range entries {
		pid := inodeMap[e.Inode]
		fmt.Printf("%-21s %-21s %-13s PID:%d\n",
			fmt.Sprintf("%s:%d", e.LocalIP, e.LocalPort),
			fmt.Sprintf("%s:%d", e.RemoteIP, e.RemotePort),
			e.State,
			pid,
		)
	}
}
