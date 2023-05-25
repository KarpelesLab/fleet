package fleet

import (
	"fmt"
	"io/fs"
	"log"
)

type RpcEndpoint func(any) (any, error)

var (
	rpcE = make(map[string]RpcEndpoint)
)

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
