package fleet

import (
	"io/fs"
	"sync"
)

type CustomHandler func(p *Peer, data []byte) error

var (
	customHandlers   = make(map[uint16]CustomHandler)
	customHandlersLk sync.RWMutex
)

func SetCustomHandler(pc uint16, h CustomHandler) {
	customHandlersLk.Lock()
	defer customHandlersLk.Unlock()

	customHandlers[pc] = h
}

func getCustomHandler(pc uint16) CustomHandler {
	customHandlersLk.RLock()
	defer customHandlersLk.RUnlock()

	if v, ok := customHandlers[pc]; ok {
		return v
	}
	return nil
}

func callCustomHandler(p *Peer, pc uint16, data []byte) error {
	h := getCustomHandler(pc)
	if h == nil {
		return fs.ErrNotExist
	}
	return h(p, data)
}
