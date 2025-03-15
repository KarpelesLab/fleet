// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
)

// RpcEndpoint represents a callback function for the legacy RPC system.
// It receives arbitrary data and returns a response and/or error.
type RpcEndpoint func(any) (any, error)

// Global registry of RPC endpoints by name
var (
	rpcE = make(map[string]RpcEndpoint)
)

// RPC defines the interface for a named RPC communication channel.
// Applications can create RPC instances for specific endpoints, making it
// easy to send and receive messages between peers in a structured way.
type RPC interface {
	// All sends data to all other RPC instances on the fleet with the same name
	// and collects responses from all peers. This is useful for querying all
	// peers for information or triggering actions across the entire fleet.
	All(ctx context.Context, data []byte) ([]any, error)

	// Broadcast sends data to all other RPC instances on the fleet with the same name
	// but does not wait for responses. This is efficient for notifications or
	// updates that don't require confirmation.
	Broadcast(ctx context.Context, data []byte) error

	// Request sends data to a specific peer's RPC instance with the same name
	// and returns the response. This is for peer-to-peer communication when
	// you need a reply from a specific node.
	Request(ctx context.Context, id string, data []byte) ([]byte, error)

	// Send sends data to a specific peer's RPC instance with the same name
	// but ignores any response. This is useful for fire-and-forget messages.
	Send(ctx context.Context, id string, data []byte) error

	// Self returns the ID of the local peer, which can be used by other peers
	// to direct messages to this instance using Request() or Send().
	Self() string

	// ListOnlinePeers returns a list of currently connected peer names.
	// This helps in discovering available peers for communication.
	ListOnlinePeers() []string

	// CountAllPeers returns the total number of known peers, whether they're
	// currently connected or not. This gives a sense of the fleet size.
	CountAllPeers() int

	// Connect registers a callback function that will be called whenever this
	// RPC instance receives a message. The callback can process the message
	// and optionally return a response.
	Connect(cb func(context.Context, []byte) ([]byte, error))
}

// rpcInstance implements the RPC interface for a specific named endpoint.
// It provides the connection between the high-level RPC interface and the
// low-level packet communication.
type rpcInstance struct {
	a    *Agent                                        // Parent agent
	name string                                        // Endpoint name
	cb   func(context.Context, []byte) ([]byte, error) // Callback for incoming messages
}

// SetRpcEndpoint registers a callback function for a named RPC endpoint.
// When an RPC call is received for this endpoint, the callback will be invoked.
//
// Parameters:
//   - e: The endpoint name
//   - f: The callback function to handle requests to this endpoint
func SetRpcEndpoint(e string, f RpcEndpoint) {
	rpcE[e] = f
}

// CallRpcEndpoint invokes the named RPC endpoint on the local machine.
// This is used internally when receiving RPC requests from remote peers.
//
// Parameters:
//   - e: The endpoint name
//   - p: The payload data
//
// Returns:
//   - The result of the RPC call
//   - An error if the endpoint doesn't exist or the call fails
func CallRpcEndpoint(e string, p any) (res any, err error) {
	// Recover from panics in the endpoint handler to prevent crashes
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("[fleet] Panic in RPC %s: %s", e, r),
				"event", "fleet:rpc:panic", "category", "go.panic")
			err = fmt.Errorf("rpc call panic recovered: %s", r)
		}
	}()

	// Look up the endpoint in the registry
	ep, ok := rpcE[e]
	if !ok {
		return nil, fs.ErrNotExist
	}

	// Call the endpoint handler with the payload
	return ep(p)
}

// NewRpcInstance creates a new RPC instance for a specific named endpoint.
// This allows applications to create communication channels for specific purposes.
//
// Parameters:
//   - name: The endpoint name, which should be unique for this application
//
// Returns:
//   - An RPC interface for the specified endpoint
//   - An error if the operation fails
func (a *Agent) NewRpcInstance(name string) (RPC, error) {
	i := &rpcInstance{
		name: name, // Set the endpoint name
		a:    a,    // Link to the parent agent
	}
	// Register this instance's call method as the endpoint handler
	SetRpcEndpoint(name, i.call)

	return i, nil
}

// All sends data to all peers and collects responses.
// This implements the RPC.All interface method.
func (i *rpcInstance) All(ctx context.Context, data []byte) ([]any, error) {
	return i.a.AllRpcRequest(ctx, i.name, data)
}

// Broadcast sends data to all peers without waiting for responses.
// This implements the RPC.Broadcast interface method.
func (i *rpcInstance) Broadcast(ctx context.Context, data []byte) error {
	_, err := i.a.BroadcastRpcBin(ctx, i.name, data)
	return err
}

// Request sends data to a specific peer and returns the response.
// This implements the RPC.Request interface method.
//
// Parameters:
//   - ctx: Context for the operation
//   - id: The ID of the target peer
//   - data: The data to send
//
// Returns:
//   - The response data
//   - An error if the operation fails
func (i *rpcInstance) Request(ctx context.Context, id string, data []byte) ([]byte, error) {
	return i.a.RpcRequest(ctx, id, i.name, data)
}

// Send sends data to a specific peer without waiting for a response.
// This implements the RPC.Send interface method.
//
// Parameters:
//   - ctx: Context for the operation
//   - id: The ID of the target peer
//   - data: The data to send
//
// Returns:
//   - An error if the operation fails
func (i *rpcInstance) Send(ctx context.Context, id string, data []byte) error {
	return i.a.RpcSend(ctx, id, i.name, data)
}

// Self returns the ID of the local agent.
// This implements the RPC.Self interface method.
func (i *rpcInstance) Self() string {
	return i.a.Id()
}

// Connect registers a callback function for incoming messages to this endpoint.
// This implements the RPC.Connect interface method.
//
// Parameters:
//   - cb: The callback function to handle incoming messages
func (i *rpcInstance) Connect(cb func(context.Context, []byte) ([]byte, error)) {
	i.cb = cb
}

// ListOnlinePeers returns a list of names of currently connected peers.
// This implements the RPC.ListOnlinePeers interface method.
func (i *rpcInstance) ListOnlinePeers() []string {
	peers := i.a.GetPeers()
	res := make([]string, 0, len(peers))
	for _, p := range peers {
		res = append(res, p.name)
	}
	return res
}

// CountAllPeers returns the total number of known peers.
// This implements the RPC.CountAllPeers interface method.
func (i *rpcInstance) CountAllPeers() int {
	return int(i.a.GetPeersCount())
}

// call is the internal callback handler for this RPC instance.
// It's registered as the endpoint handler in NewRpcInstance.
//
// Parameters:
//   - v: The incoming data (expected to be a []byte)
//
// Returns:
//   - The response data
//   - An error if no callback is registered or if the operation fails
func (i *rpcInstance) call(v any) (any, error) {
	if cb := i.cb; cb != nil {
		return cb(context.Background(), v.([]byte))
	}
	return nil, fs.ErrNotExist
}
