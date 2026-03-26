package main

import (
	"flag"
	"fmt"
	"github.com/treytuscai/meshwatch/internal/discovery"
	"log"
	"os"
	"text/tabwriter"
	"time"
)

func main() {
	watch := flag.Bool("watch", false, "continuously refresh")
	flag.Parse()

	for {
		scan()
		if !*watch {
			break
		}
		time.Sleep(2 * time.Second)
		fmt.Print("\033[H\033[2J") // clear screen
	}
}

func scan() {
	entries, err := discovery.ParseProcNetTCP()
	if err != nil {
		log.Fatal(err)
	}
	inodeMap, err := discovery.InodeToProcess()
	if err != nil {
		log.Fatal(err)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "LOCAL\tREMOTE\tSTATE\tPROCESS\n")
	for _, e := range entries {
		pid := inodeMap[e.Inode]
		info, err := discovery.GetProcessInfo(pid)
		if err != nil {
			continue
		}
		fmt.Fprintf(w, "%s:%d\t%s:%d\t%s\t%s\n",
			e.LocalIP, e.LocalPort,
			e.RemoteIP, e.RemotePort,
			e.State,
			info.Name,
		)
	}
	w.Flush()
}
