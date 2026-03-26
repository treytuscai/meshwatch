// Package discovery provides tools for scanning Linux /proc
// to discover running services and their network connections.
package discovery

// Protocol identifies the transport protocol.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoTCP6 Protocol = "tcp6"
)

type Node struct {
	ID      string
	PID     int
	Name    string
	CmdLine string
	Ports   []uint64
}

type Edge struct {
    // what two things does it connect?
    // what metadata matters?
}

type Topology struct {
    Nodes map[string]*Node
    Edges map[string]*Edge
}