package fleet

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
)

// RpcEndpoint represents a callback function for the legacy RPC system
type RpcEndpoint func(any) (any, error)

var (
	rpcE = make(map[string]RpcEndpoint)
)

type RPC interface {
	// All will send a given data object to all other RPC instances on the fleet
	// and will collect responses
	All(ctx context.Context, data []byte) ([]any, error)

	// Broadcast will do the same as All but will not wait for responses
	Broadcast(ctx context.Context, data []byte) error

	// Request will send a given object to a specific peer and return the response
	Request(ctx context.Context, id string, data []byte) ([]byte, error)

	// SEnd will send a given object to a specific peer but ignore the response
	Send(ctx context.Context, id string, data []byte) error

	// Self will return the id of the local peer, can be used for other instances
	// to contact here with Send().
	Self() string

	// ListOnlinePeers returns a list of connected peers
	ListOnlinePeers() []string

	// CountAllPeers return the number of known connected or offline peers
	CountAllPeers() int

	// Connect connects this RPC instance incoming events to a given function
	// that will be called each time an event is received.
	Connect(cb func(context.Context, []byte) ([]byte, error))
}

type rpcInstance struct {
	a    *Agent
	name string
	cb   func(context.Context, []byte) ([]byte, error)
}

func SetRpcEndpoint(e string, f RpcEndpoint) {
	rpcE[e] = f
}

// CallRpcEndpoint will call the named RPC endpoint on the local machine
func CallRpcEndpoint(e string, p any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error(fmt.Sprintf("[fleet] Panic in RPC %s: %s", e, r), "event", "fleet:rpc:panic", "category", "go.panic")
			err = fmt.Errorf("rpc call panic recovered: %s", r)
		}
	}()

	ep, ok := rpcE[e]
	if !ok {
		return nil, fs.ErrNotExist
	}

	return ep(p)
}

func (a *Agent) NewRpcInstance(name string) (RPC, error) {
	i := &rpcInstance{
		name: name,
		a:    a,
	}
	SetRpcEndpoint(name, i.call)

	return i, nil
}

func (i *rpcInstance) All(ctx context.Context, data []byte) ([]any, error) {
	return i.a.AllRpcRequest(ctx, i.name, data)
}

func (i *rpcInstance) Broadcast(ctx context.Context, data []byte) error {
	_, err := i.a.BroadcastRpcBin(ctx, i.name, data)
	return err
}

func (i *rpcInstance) Request(ctx context.Context, id string, data []byte) ([]byte, error) {
	return i.a.RpcRequest(ctx, id, i.name, data)
}

func (i *rpcInstance) Send(ctx context.Context, id string, data []byte) error {
	return i.a.RpcSend(ctx, id, i.name, data)
}

func (i *rpcInstance) Self() string {
	return i.a.Id()
}

func (i *rpcInstance) Connect(cb func(context.Context, []byte) ([]byte, error)) {
	i.cb = cb
}

func (i *rpcInstance) ListOnlinePeers() []string {
	peers := i.a.GetPeers()
	res := make([]string, 0, len(peers))
	for _, p := range peers {
		res = append(res, p.name)
	}
	return res
}

func (i *rpcInstance) CountAllPeers() int {
	return int(i.a.GetPeersCount())
}

func (i *rpcInstance) call(v any) (any, error) {
	if cb := i.cb; cb != nil {
		return cb(context.Background(), v.([]byte))
	}
	return nil, fs.ErrNotExist
}
