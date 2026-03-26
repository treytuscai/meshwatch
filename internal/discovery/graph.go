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
	ID          string    `json:"id"`
	PID         int       `json:"pid"`
	Name        string    `json:"name"`
	CmdLine     string    `json:"cmdline"`
	ListenPorts []uint64  `json:"listen_ports"`
	FirstSeen   time.Time `json:"first_seen"`
}

// Edge represents a network connection between two nodes.
type Edge struct {
	ID        string    `json:"id"`
	SourceID  string    `json:"source_id"`
	TargetID  string    `json:"target_id"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  Protocol  `json:"protocol"`
	State     string    `json:"state"`
	FirstSeen time.Time `json:"first_seen"`
}

// Topology is the full service graph — thread-safe.
type Topology struct {
	mu        sync.RWMutex
	Nodes     map[string]*Node `json:"nodes"`
	Edges     map[string]*Edge `json:"edges"`
	UpdatedAt time.Time        `json:"updated_at"`
}

// NewTopology creates an empty topology graph.
func NewTopology() *Topology {
	return &Topology{
		Nodes: make(map[string]*Node),
		Edges: make(map[string]*Edge),
	}
}

// UpsertNode adds or updates a node in the graph.
func (t *Topology) UpsertNode(n *Node) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.Nodes[n.ID]; ok {
		// Preserve first_seen, update everything else
		n.FirstSeen = existing.FirstSeen
	}
	t.Nodes[n.ID] = n
	t.UpdatedAt = time.Now()
}

// UpsertEdge adds or updates an edge in the graph.
func (t *Topology) UpsertEdge(e *Edge) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if existing, ok := t.Edges[e.ID]; ok {
		// Preserve first_seen, update everything else
		e.FirstSeen = existing.FirstSeen
	}
	t.Edges[e.ID] = e
	t.UpdatedAt = time.Now()
}

// Prune removes nodes and edges not present in the given sets of IDs.
func (t *Topology) Prune(activeNodeIDs, activeEdgeIDs map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id := range t.Nodes {
		if !activeNodeIDs[id] {
			delete(t.Nodes, id)
		}
	}

	for id := range t.Edges {
		if !activeEdgeIDs[id] {
			delete(t.Edges, id)
		}
	}
}

// TopologySnapshot is the JSON-serializable form of a Topology.
type TopologySnapshot struct {
	Nodes     []Node    `json:"nodes"`
	Edges     []Edge    `json:"edges"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Snapshot returns a deep-ish copy of the topology for safe serialization.
func (t *Topology) Snapshot() TopologySnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()
	snap := TopologySnapshot{
		Nodes:     make([]Node, 0, len(t.Nodes)),
		Edges:     make([]Edge, 0, len(t.Edges)),
		UpdatedAt: t.UpdatedAt,
	}

	for _, n := range t.Nodes {
		snap.Nodes = append(snap.Nodes, *n)
	}
	for _, e := range t.Edges {
		snap.Edges = append(snap.Edges, *e)
	}
	return snap
}
