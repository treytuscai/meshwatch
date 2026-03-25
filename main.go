package main

import (
	"github.com/treytuscai/meshwatch/internal/discovery"
	"log"
	"fmt"
)

func main() {
	entries, err := discovery.ParseProcNetTCP("/proc/net/tcp")
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range entries {
		fmt.Printf("%-21s %-21s %-13s %d\n",
			fmt.Sprintf("%s:%d", e.LocalIP, e.LocalPort),
			fmt.Sprintf("%s:%d", e.RemoteIP, e.RemotePort),
			e.State,
			e.Inode,
		)
	}
}
