// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import "sync"

// Global singleton instance management
// These variables manage the globally accessible Agent instance
var (
	// self holds the global Agent instance
	self *Agent

	// selfLk protects access to the self variable
	selfLk sync.RWMutex

	// selfCond is a condition variable for notifying when self becomes available
	selfCond = sync.NewCond(selfLk.RLocker())
)

// Self returns the global Agent instance that was created by New().
// If no Agent has been created yet, this function will block until
// one is available.
//
// IMPORTANT: Due to the blocking behavior, this function should not be
// used in init() functions. Only use it in goroutines or after an Agent
// has been explicitly created.
//
// Returns:
//   - The global Agent instance
func Self() *Agent {
	selfLk.RLock()
	defer selfLk.RUnlock()

	// Wait until an Agent instance is available
	for {
		if self != nil {
			return self
		}
		selfCond.Wait() // Block until setSelf() calls Broadcast()
	}
}

// selfNoWait returns the global Agent instance without waiting.
// This returns nil if no Agent has been created yet.
//
// Returns:
//   - The global Agent instance, or nil if not available
func selfNoWait() *Agent {
	selfLk.RLock()
	defer selfLk.RUnlock()
	return self
}

// setSelf sets the global Agent instance.
// This is called during Agent initialization to make the instance
// globally available and wake up any goroutines waiting in Self().
//
// Parameters:
//   - a: The Agent instance to set as the global instance
func setSelf(a *Agent) {
	selfLk.Lock()
	defer selfLk.Unlock()

	// Only set if not already set
	if self == nil {
		self = a
	}

	// Notify all waiters that an Agent is now available
	selfCond.Broadcast()
}

// IsReady returns whether the fleet subsystem is fully initialized and ready.
// This checks both that an Agent exists and that it reports ready status.
//
// Returns:
//   - true if the fleet is fully initialized and ready, false otherwise
func IsReady() bool {
	a := selfNoWait()

	if a == nil {
		return false // No Agent exists
	}
	return a.GetStatus() == 1 // Status 1 means ready
}
