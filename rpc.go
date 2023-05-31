package fleet

import (
	"context"
	"fmt"
	"io/fs"
	"log"
)

type RpcEndpoint func(any) (any, error)

var (
	rpcE = make(map[string]RpcEndpoint)
)

type RPC interface {
	// All will send a given data object to all other RPC instances on the fleet
	// and will collect responses
	All(ctx context.Context, data any) ([]any, error)

	// Broadcast will do the same as All but will not wait for responses
	Broadcast(ctx context.Context, data any) error

	// Send will send a given object to a specific peer and return the response
	Send(ctx context.Context, id string, data any) (any, error)

	// Self will return the id of the local peer, can be used for other instances
	// to contact here with Send()
	Self() string

	// Connect connects this RPC instance incoming events to a given function
	// that will be called each time an event is received.
	Connect(cb func(context.Context, any) (any, error))
}

type rpcInstance struct {
	a    *Agent
	name string
	cb   func(context.Context, any) (any, error)
}

func SetRpcEndpoint(e string, f RpcEndpoint) {
	rpcE[e] = f
}

// CallRpcEndpoint will call the named RPC endpoint on the local machine
func CallRpcEndpoint(e string, p any) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[fleet] Panic in RPC %s: %s", e, r)
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

func (i *rpcInstance) All(ctx context.Context, data any) ([]any, error) {
	return i.a.AllRPC(ctx, i.name, data)
}

func (i *rpcInstance) Broadcast(ctx context.Context, data any) error {
	return i.a.BroadcastRpc(ctx, i.name, data)
}

func (i *rpcInstance) Send(ctx context.Context, id string, data any) (any, error) {
	return i.a.RPC(ctx, id, i.name, data)
}

func (i *rpcInstance) Self() string {
	return i.a.Id()
}

func (i *rpcInstance) Connect(cb func(context.Context, any) (any, error)) {
	i.cb = cb
}

func (i *rpcInstance) call(v any) (any, error) {
	if cb := i.cb; cb != nil {
		return cb(context.Background(), v)
	}
	return nil, fs.ErrNotExist
}
