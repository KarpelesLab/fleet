// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"io/fs"
	"sync"
)

// CustomHandler is a function type for handling custom packet types.
// Applications can register handlers for custom packet codes in the range
// 0xa000-0xafff to extend the fleet protocol with application-specific functionality.
//
// Parameters:
//   - p: The peer that sent the packet
//   - data: The raw packet data
//
// Returns:
//   - An error if handling fails, nil otherwise
type CustomHandler func(p *Peer, data []byte) error

// Global registry for custom packet handlers
var (
	// Map of packet codes to their handlers
	customHandlers = make(map[uint16]CustomHandler)

	// Mutex to protect concurrent access to the handlers map
	customHandlersLk sync.RWMutex
)

// SetCustomHandler registers a handler function for a custom packet type.
// This allows applications to extend the fleet protocol with custom
// packet types and handling logic.
//
// The packet code should be in the range 0xa000-0xafff, which can be
// obtained using the Custom() function.
//
// Parameters:
//   - pc: The packet code to register the handler for
//   - h: The handler function to call when this packet type is received
func SetCustomHandler(pc uint16, h CustomHandler) {
	customHandlersLk.Lock()
	defer customHandlersLk.Unlock()

	customHandlers[pc] = h
}

// getCustomHandler retrieves the handler for a given packet code.
// Returns nil if no handler is registered for the code.
//
// Parameters:
//   - pc: The packet code to get the handler for
//
// Returns:
//   - The registered handler, or nil if none exists
func getCustomHandler(pc uint16) CustomHandler {
	customHandlersLk.RLock()
	defer customHandlersLk.RUnlock()

	if v, ok := customHandlers[pc]; ok {
		return v
	}
	return nil
}

// callCustomHandler invokes the appropriate handler for a custom packet.
// This is called by the peer packet handling logic when a custom packet
// is received.
//
// Parameters:
//   - p: The peer that sent the packet
//   - pc: The packet code
//   - data: The raw packet data
//
// Returns:
//   - An error if handling fails or no handler is registered, nil otherwise
func callCustomHandler(p *Peer, pc uint16, data []byte) error {
	h := getCustomHandler(pc)
	if h == nil {
		return fs.ErrNotExist // No handler registered for this packet code
	}
	return h(p, data)
}
