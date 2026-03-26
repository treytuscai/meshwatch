// Package discovery provides tools for scanning Linux /proc
// to discover running services and their network connections.
package discovery

import (
	"sync"
	"time"
)

// Protocol identifies the transport protocol.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoTCP6 Protocol = "tcp6"
)

// Node represents a running process or container on the system.
type Node struct {
	ID          string
	PID         int
	Name        string
	CmdLine     string
	ListenPorts []uint64
	FirstSeen   time.Time
}

// Edge represents a network connection between two nodes.
type Edge struct {
	ID        string
	SourceID  string
	TargetID  string
	SrcPort   uint16
	DstPort   uint16
	Protocol  Protocol
	State     string
	FirstSeen time.Time
}

// Topology is the full service graph — thread-safe.
type Topology struct {
	mu        sync.RWMutex
	Nodes     map[string]*Node
	Edges     map[string]*Edge
	UpdatedAt time.Time
}

// NewTopology creates an empty topology graph.
func NewTopology() *Topology {
	return &Topology{
		Nodes: make(map[string]*Node),
		Edges: make(map[string]*Edge),
	}
}