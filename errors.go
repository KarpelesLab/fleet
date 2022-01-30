package fleet

import "errors"

var (
	ErrWriteQueueFull = errors.New("peer write queue is full")
	ErrPeerNoRoute    = errors.New("no route to peer")
)
