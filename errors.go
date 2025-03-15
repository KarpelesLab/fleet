// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import "errors"

// Error constants used throughout the fleet library.
// These provide standardized errors for common failure conditions.
var (
	// ErrWriteQueueFull is returned when attempting to send data to a peer whose
	// write queue is already at capacity, typically due to network congestion.
	ErrWriteQueueFull = errors.New("peer write queue is full")

	// ErrPeerNoRoute is returned when attempting to send data to a peer that
	// cannot be reached, either because it doesn't exist or because no path
	// exists to that peer.
	ErrPeerNoRoute = errors.New("no route to peer")

	// ErrConnectionClosed is returned when attempting to use a connection that
	// has already been closed, either by this node or the remote peer.
	ErrConnectionClosed = errors.New("connection has been closed")

	// ErrInvalidLegacy is returned when attempting an operation that is not
	// supported on legacy peers (peers using older protocol versions).
	ErrInvalidLegacy = errors.New("invalid operation on legacy peer")

	// ErrInvalidLockName is returned when attempting to acquire a lock with an
	// invalid name, such as an empty string.
	ErrInvalidLockName = errors.New("invalid lock name")

	// ErrCancelledLock is returned when a lock acquisition request is cancelled
	// externally, typically due to a competing lock.
	ErrCancelledLock = errors.New("lock request has been cancelled")

	// ErrEndpointNameLen is returned when an RPC endpoint name exceeds the
	// maximum allowed length (65535 bytes).
	ErrEndpointNameLen = errors.New("RPC endpoint name length too long")
)
