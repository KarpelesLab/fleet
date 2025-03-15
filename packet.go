// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"encoding/gob"
	"time"

	"github.com/KarpelesLab/rchan"
)

// Register all packet types with gob for serialization
func init() {
	gob.Register(&PacketHandshake{})
	gob.Register(&PacketAnnounce{})
	gob.Register(&PacketRpc{})
	gob.Register(&PacketRpcResponse{})
	gob.Register(&PacketDbRecord{})
	gob.Register(DbStamp{})
	gob.Register(&PacketDbVersions{})
	gob.Register(&PacketDbVersionsEntry{})
	gob.Register(&PacketDbRequest{})
}

// Packet is the generic interface for all packets exchanged between peers.
// Concrete packet types are registered with gob for serialization.
type Packet any

// PacketHandshake is sent when a peer connection is first established.
// It contains identifying information about the peer.
type PacketHandshake struct {
	Id       string    // Unique identifier for the peer
	Name     string    // Human-readable name
	Division string    // Logical grouping/location (e.g., datacenter)
	Now      time.Time // Current time, used for clock synchronization

	// Version information for updates
	Git     string // Git commit or tag
	Build   string // Build timestamp
	Channel string // Update channel
}

// PacketAnnounce is sent periodically by peers to announce their presence and status.
// It contains current state information about the peer.
type PacketAnnounce struct {
	Id   string         // Peer identifier
	Now  time.Time      // Current timestamp
	Idx  uint64         // Announcement index (monotonically increasing)
	NumG uint32         // Number of goroutines (for load balancing)
	AZ   string         // Availability zone/division
	Meta map[string]any // Custom metadata
}

// PacketRpc carries RPC requests between peers.
// It's used to invoke remote procedures and pass serialized data.
type PacketRpc struct {
	TargetId string   // Target peer ID
	SourceId string   // Source peer ID
	Endpoint string   // RPC endpoint/method name
	R        rchan.Id // Response channel ID
	Data     any      // Payload data
}

// PacketRpcResponse carries RPC responses back to the requestor.
// It contains the result of an RPC call or an error message.
type PacketRpcResponse struct {
	TargetId string   // Target peer ID
	SourceId string   // Source peer ID
	R        rchan.Id // Response channel ID (matches request)
	Data     any      // Response data
	Error    string   // Error message (if any)
	HasError bool     // Whether an error occurred
}

// PacketDbRecord is used to synchronize database records between peers.
// It contains a database key-value pair along with a timestamp.
type PacketDbRecord struct {
	TargetId string  // Target peer ID
	SourceId string  // Source peer ID
	Stamp    DbStamp // Timestamp for versioning
	Bucket   []byte  // Database bucket (typically "app")
	Key, Val []byte  // Database key and value
}

// PacketDbVersions signals what database records are available in a peer.
// It's typically sent when a connection is established to synchronize databases.
type PacketDbVersions struct {
	Info []*PacketDbVersionsEntry // List of available database entries
}

// PacketDbVersionsEntry represents a single database record in the versions list.
// It contains metadata about the record but not the actual value.
type PacketDbVersionsEntry struct {
	Stamp  DbStamp // Timestamp for versioning
	Bucket []byte  // Database bucket (typically "app")
	Key    []byte  // Database key
}

// PacketDbRequest requests a specific database record from a peer.
// The peer will respond with a PacketDbRecord containing the requested data.
type PacketDbRequest struct {
	TargetId string // Target peer ID
	SourceId string // Source peer ID
	Bucket   []byte // Database bucket (typically "app")
	Key      []byte // Database key to retrieve
}
