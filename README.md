# Fleet

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/fleet.svg)](https://pkg.go.dev/github.com/KarpelesLab/fleet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Fleet is a distributed peer-to-peer communication framework written in Go. It enables automatic peer discovery, secure communication, distributed operations, and synchronized data across a network of nodes (agents).

## Features

- **Automatic Peer Discovery** - Discovers and connects to peers using the Spot protocol
- **Secure Communication** - TLS-encrypted connections with certificate verification and optional TPM key support
- **Distributed Database** - Synchronized key-value store (BoltDB) with automatic replication and conflict resolution
- **Remote Procedure Calls** - High-level gob-serialized and binary RPC with multiple broadcast patterns
- **Distributed Locking** - Consensus-based locks for cluster-wide resource coordination
- **Network Services** - QUIC transport for efficient, multiplexed connections

## Installation

```bash
go get github.com/KarpelesLab/fleet
```

Requires Go 1.24 or later.

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/KarpelesLab/fleet"
)

func main() {
    // Create a new agent
    agent := fleet.New()

    // Wait for the agent to be ready
    agent.WaitReady()

    // Register an RPC endpoint
    fleet.SetRpcEndpoint("hello", func(data any) (any, error) {
        return "Hello from " + agent.Id(), nil
    })

    // Call RPC on a peer
    peers := agent.GetPeers()
    if len(peers) > 0 {
        result, err := agent.RPC(context.Background(), peers[0].Id(), "hello", nil)
        if err != nil {
            log.Fatal(err)
        }
        log.Printf("Response: %v", result)
    }
}
```

## Core Concepts

### Agent

The `Agent` is the main component representing a node in the fleet. It manages peer connections, database synchronization, and communication.

```go
// Access the global agent singleton
agent := fleet.Self()

// Get agent identity
id := agent.Id()
name, hostname := agent.Name()
division := agent.Division()
```

### Peers

Peers represent remote nodes in the fleet.

```go
// Get all connected peers
peers := agent.GetPeers()

// Get a specific peer
peer := agent.GetPeer("peer-id")

// Get peer by name
peer := agent.GetPeerByName("node-name")

// Check peer status
if peer.IsAlive() {
    log.Printf("Peer %s is alive", peer.Name())
}
```

### RPC Communication

Fleet supports multiple RPC patterns:

```go
ctx := context.Background()

// Direct RPC to a specific peer
result, err := agent.RPC(ctx, "peer-id", "endpoint", data)

// Broadcast to all peers (fire-and-forget)
err := agent.BroadcastRpc(ctx, "endpoint", data)

// Query all peers and collect responses
results, err := agent.AllRPC(ctx, "endpoint", data)

// Route to least-busy peer in a division
err := agent.AnyRpc(ctx, "division", "endpoint", data)

// Target peers by division
results, err := agent.DivisionRpc(ctx, "us-west", "endpoint", data)
```

### Distributed Database

Fleet provides a synchronized key-value store across all peers:

```go
// Store data (automatically replicated)
err := agent.DbSet("mykey", []byte("myvalue"))

// Retrieve data
value, err := agent.DbGet("mykey")

// Delete data
err := agent.DbDelete("mykey")

// Watch for changes
agent.DbWatch("mykey", func(key string, val []byte) {
    log.Printf("Key %s changed to %s", key, string(val))
})

// Get keys with prefix
keys := agent.DbKeys("app", "prefix:")
```

**Buckets:**
- `app` - User application data (default)
- `global` - System-wide data
- `local` - Non-replicated local data

### Distributed Locking

Consensus-based distributed locks:

```go
// Try to acquire a lock (non-blocking)
lock, err := agent.TryLock("resource-name")
if err != nil {
    log.Printf("Could not acquire lock: %v", err)
}

// Acquire a lock (blocking with context)
lock, err := agent.Lock(ctx, "resource-name")
if err != nil {
    log.Fatal(err)
}
defer lock.Release()

// Use the locked resource...
```

### Network Services

Create custom services on the fleet network:

```go
// Create a service listener
listener, err := agent.AddService("myservice")
if err != nil {
    log.Fatal(err)
}

// Accept connections
for {
    conn, err := listener.Accept()
    if err != nil {
        break
    }
    go handleConnection(conn)
}

// Connect to a peer's service
conn, err := agent.Connect("peer-id", "myservice")
```

### Metadata

Store and broadcast peer-specific metadata:

```go
// Set metadata (broadcast to all peers)
agent.MetaSet("status", "online")
agent.MetaSet("version", "1.0.0")

// Read peer metadata
for _, peer := range agent.GetPeers() {
    meta := peer.Meta()
    log.Printf("Peer %s status: %v", peer.Name(), meta["status"])
}
```

## Architecture

```
Application Layer (RPC endpoints, DB operations, locks)
                ↓
    Packet Protocol Layer (Binary packets)
                ↓
    Database Sync Layer (Versioned records)
                ↓
      Network Layer (Spot + QUIC transport)
                ↓
       TLS/Encryption Layer
                ↓
        Physical Network
```

**Packet Types:**
- `PacketHandshake` - Initial peer identification
- `PacketAnnounce` - Periodic status updates
- `PacketRpc` - RPC requests/responses
- `PacketDbRecord` - Database synchronization
- `PacketSeed` - Cluster seed exchange
- `PacketLock*` - Distributed locking operations
- `PacketPing/Pong` - Health monitoring

## Build & Test

```bash
# Build with formatting
make

# Install dependencies
make deps

# Run all tests
make test

# Run a specific test
go test -v github.com/KarpelesLab/fleet -run TestName
```

## Dependencies

Key dependencies:
- [quic-go](https://github.com/quic-go/quic-go) - QUIC protocol implementation
- [bbolt](https://go.etcd.io/bbolt) - BoltDB key-value store
- [spotlib](https://github.com/KarpelesLab/spotlib) - Spot protocol for peer discovery
- [cryptutil](https://github.com/KarpelesLab/cryptutil) - Cryptographic utilities

## License

MIT License - see [LICENSE](LICENSE) for details.
