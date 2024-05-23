package fleet

import "errors"

var (
	ErrWriteQueueFull   = errors.New("peer write queue is full")
	ErrPeerNoRoute      = errors.New("no route to peer")
	ErrConnectionClosed = errors.New("connection has been closed")
	ErrInvalidLegacy    = errors.New("invalid operation on legacy peer")
	ErrInvalidLockName  = errors.New("invalid lock name")
	ErrCancelledLock    = errors.New("lock request has been cancelled")
	ErrEndpointNameLen  = errors.New("RPC endpoint name length too long")
)
