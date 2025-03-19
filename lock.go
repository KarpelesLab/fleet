// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// LocalLock represents a successfully acquired distributed lock.
// This is the type returned to users when they acquire a lock, and
// it provides methods to release the lock when done.
type LocalLock struct {
	lk   *globalLock // Reference to the underlying global lock
	once sync.Once   // Ensures release() is done only once
}

// globalLock represents a distributed lock in the fleet system.
// It coordinates consensus among peers to ensure only one node
// can hold a particular named lock at a time.
type globalLock struct {
	name    string      // Lock name/identifier
	t       uint64      // Timestamp when lock was created (used for conflict resolution)
	owner   string      // ID of the node that owns the lock
	ch      chan uint32 // Channel for lock status updates
	status  uint32      // Lock status: 0=new/pending, 1=confirmed, 2=failed/released
	local   bool        // Whether this lock was initiated by the local node
	lk      sync.Mutex  // Mutex for modifying aye/nay lists
	aye     []string    // List of peer IDs that approved the lock
	nay     []string    // List of peer IDs that rejected the lock
	a       *Agent      // Reference to the parent agent
	timeout time.Time   // When this lock expires
}

// getLock retrieves an active lock with the given name if it exists.
// Returns nil if no valid lock with the name exists.
//
// Parameters:
//   - name: The name of the lock to retrieve
//
// Returns:
//   - The lock if found and valid, nil otherwise
func (a *Agent) getLock(name string) *globalLock {
	a.globalLocksLk.RLock()
	defer a.globalLocksLk.RUnlock()
	v, ok := a.globalLocks[name]
	if ok && v.valid() {
		return v
	}
	return nil
}

// getLocks returns a list of all active locks.
// This is primarily used for debugging and monitoring.
//
// Returns:
//   - A slice of all global locks currently tracked by this agent
func (a *Agent) getLocks() []*globalLock {
	a.globalLocksLk.RLock()
	defer a.globalLocksLk.RUnlock()

	res := make([]*globalLock, 0, len(a.globalLocks))

	for _, l := range a.globalLocks {
		res = append(res, l)
	}
	return res
}

// DebugLocks writes debugging information about all locks to the provided writer.
// This is useful for diagnosing lock-related issues.
//
// Parameters:
//   - w: The writer to output debug information to
func (a *Agent) DebugLocks(w io.Writer) {
	lks := a.getLocks()

	fmt.Fprintf(w, "Locks:\n")

	for _, l := range lks {
		fmt.Fprintf(w, " * %s t=%d owner=%s status=%d local=%v timeout=%s\n",
			l.name, l.t, l.owner, l.status, l.local, l.timeout)
	}
}

// makeLock creates a new lock with the given parameters.
// If a lock with the same name already exists, it will be replaced if force is true
// or if it's no longer valid.
//
// Parameters:
//   - name: The name of the lock
//   - owner: The ID of the peer that will own the lock
//   - tm: Timestamp for ordering/conflict resolution
//   - force: Whether to force creation even if a valid lock exists
//
// Returns:
//   - The newly created lock, or nil if a valid lock already exists and force is false
func (a *Agent) makeLock(name, owner string, tm uint64, force bool) *globalLock {
	a.globalLocksLk.Lock()
	defer a.globalLocksLk.Unlock()

	// Check if a lock with this name already exists
	if v, ok := a.globalLocks[name]; ok {
		if !force && v.valid() {
			// Don't replace a valid lock unless forced
			return nil
		}
		// Disable the existing lock
		v.setStatus(2)       // Mark as failed/released
		v.broadcastRelease() // Inform all peers
	}

	// Create a new lock
	lk := &globalLock{
		name:    name,
		owner:   owner,
		t:       tm,
		ch:      make(chan uint32, 1), // Channel for status updates
		a:       a,
		timeout: time.Now().Add(30 * time.Minute), // Default timeout
	}
	// Store the lock in the global map, no need to lock the mutex yet
	// since this function holds the agent's globalLocksLk
	a.globalLocks[name] = lk
	// Lock only after adding to the map to prevent deadlock when called from other methods
	lk.lk.Lock()
	return lk
}

// release releases the lock and informs all peers.
// This cancels the lock both locally and across the fleet.
func (l *globalLock) release() {
	l.broadcastRelease() // Tell all peers the lock is released
	l.dereg()            // Remove from local tracking
}

// broadcastRelease notifies all peers that a lock has been released.
// This is only done for locks that were created locally (not in response to peer requests).
func (l *globalLock) broadcastRelease() {
	slog.Debug(fmt.Sprintf("[fleet] releasing lock %s %d %s", l.name, l.t, l.owner),
		"event", "fleet:lock:release")

	if l.local {
		// Only broadcast for locks we own
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		l.a.BroadcastPacket(ctx, PacketLockRelease, l.Key())
	}
}

// dereg removes the lock from local tracking.
// This cleans up resources and notifies waiting goroutines via the channel.
func (l *globalLock) dereg() {
	l.a.globalLocksLk.Lock()
	defer l.a.globalLocksLk.Unlock()

	v, ok := l.a.globalLocks[l.name]
	if !ok || v != l {
		// Not the same lock instance, don't modify
		return
	}

	// Remove from map and close the notification channel
	delete(l.a.globalLocks, l.name)
	close(l.ch)
}

// Key returns a binary representation of the lock's key information.
// This is used for network communication about the lock.
//
// Returns:
//   - A binary representation of the lock's name, timestamp, and owner
func (l *globalLock) Key() []byte {
	return codeLockBytes(l.name, l.t, l.owner)
}

// codeLockBytes serializes lock information into a binary format.
// This creates a byte array containing the lock name, timestamp, and owner.
//
// Parameters:
//   - name: The lock name
//   - t: Lock timestamp
//   - owner: Owner ID
//
// Returns:
//   - A binary representation of the lock information
func codeLockBytes(name string, t uint64, owner string) []byte {
	// Format: <nameLen:1><name:nameLen><timestamp:8><ownerLen:1><owner:ownerLen>
	v := make([]byte, 8+2+len(name)+len(owner))
	s := v

	// Write name length and name
	s[0] = byte(len(name))
	copy(s[1:], name)
	s = s[len(name)+1:]

	// Write timestamp
	binary.BigEndian.PutUint64(s[:8], t)
	s = s[8:]

	// Write owner length and owner
	s[0] = byte(len(owner))
	copy(s[1:], owner)

	return v
}

// decodeLockBytes deserializes lock information from a binary format.
// This parses a byte array created by codeLockBytes back into its components.
//
// Parameters:
//   - v: Binary data to parse
//
// Returns:
//   - name: The lock name
//   - t: Lock timestamp
//   - owner: Owner ID
//   - remaining: Remaining unparsed bytes
func decodeLockBytes(v []byte) (string, uint64, string, []byte) {
	// Format: <nameLen:1><name:nameLen><timestamp:8><ownerLen:1><owner:ownerLen>

	// Check if there's enough data to parse
	if len(v) < 10 {
		return "", 0, "", nil
	}

	// Parse name
	nameLen := v[0]
	if len(v) < int(nameLen)+1+8+1 { // nameLen + name + timestamp + ownerLen
		return "", 0, "", nil
	}
	name := v[1 : int(nameLen)+1]
	v = v[int(nameLen)+1:]

	// Parse timestamp
	t := binary.BigEndian.Uint64(v[:8])
	v = v[8:]

	// Parse owner
	ownerLen := v[0]
	if len(v) < int(ownerLen)+1 {
		return "", 0, "", nil
	}
	owner := v[1 : ownerLen+1]
	v = v[ownerLen+1:]

	return string(name), t, string(owner), v
}

// Lock acquires a distributed lock with the given name.
// This implements a consensus algorithm across fleet peers to ensure
// only one node can hold a particular lock at any time.
//
// The consensus algorithm works as follows:
// - If >= (1/2+1) of nodes respond "aye", the lock is confirmed
// - If >= (1/3+1) of nodes respond "nay", the lock fails and is retried
// - If neither threshold is reached within a timeout, the lock is retried
//
// Parameters:
//   - ctx: The context for the operation, which can cancel the lock attempt
//   - name: The name of the lock to acquire
//
// Returns:
//   - A LocalLock that can be used to release the lock
//   - An error if the lock cannot be acquired
func (a *Agent) Lock(ctx context.Context, name string) (*LocalLock, error) {
	if name == "" {
		return nil, ErrInvalidLockName
	}

	slog.Debug(fmt.Sprintf("[fleet] Attempting to acquire lock %s", name),
		"event", "fleet:lock:acquiretry")
	start := time.Now()

	// Main lock acquisition loop - continues until lock is acquired or context is cancelled
	for {
		// Check if the lock is already held
		lk := a.getLock(name)

		if lk != nil {
			// Lock is already acquired or being acquired by someone
			// Wait for it to be released or changed
			select {
			case <-lk.ch:
				// Status has changed (possibly released)
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		// Generate a unique timestamp for this lock attempt
		// This is used for conflict resolution if multiple nodes try to lock simultaneously
		tm := UniqueTimestamp()

		// Try to create a lock entry
		lk = a.makeLock(name, a.id, tm, false)
		if lk == nil {
			// Failed to create the lock (race condition?)
			// Check for context cancellation before retrying
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				// Continue immediately
			}
			continue
		}

		// Mark this as a locally-initiated lock (not from a remote request)
		lk.local = true
		lk.lk.Unlock() // Unlock the mutex (was locked in makeLock)

		slog.Debug(fmt.Sprintf("[fleet] Lock %s acquire attempt with t=%d", name, tm),
			"event", "fleet:lock:attempt")

		// Fast path for single-node fleets
		if a.GetPeersCount() <= 1 {
			// With no other peers, we auto-confirm the lock
			lk.setStatus(1) // Confirmed
			res := &LocalLock{lk: lk}
			runtime.SetFinalizer(res, finalizeLocalLock) // Ensure release on garbage collection
			slog.Debug(fmt.Sprintf("[fleet] Lock %s acquired in %s (no other peers)", name, time.Since(start)),
				"event", "fleet:lock:acquire_solo")
			return res, nil
		}

		// Set up a timeout for the consensus process
		timeout := time.NewTimer(5 * time.Second)
		// Send lock request to all peers
		go a.BroadcastPacket(context.Background(), PacketLockReq, lk.Key())

	acqLoop:
		// Wait for consensus or timeout
		for {
			select {
			case st, ok := <-lk.ch:
				if !ok {
					// Channel closed - lock was cancelled externally
					timeout.Stop()
					return nil, ErrCancelledLock
				}

				switch st {
				case 0:
					// Status update with no change
					break

				case 1:
					// Lock confirmed by consensus
					res := &LocalLock{lk: lk}
					runtime.SetFinalizer(res, finalizeLocalLock)
					timeout.Stop()

					// Inform all peers that the lock is confirmed
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					a.BroadcastPacket(ctx, PacketLockConfirm, lk.Key())

					slog.Debug(fmt.Sprintf("[fleet] Lock %s acquired in %s", name, time.Since(start)),
						"event", "fleet:lock:acquire_success")
					return res, nil

				case 2:
					// Lock rejected - too many "nay" votes or conflict
					lk.release()
					slog.Debug(fmt.Sprintf("[fleet] Lock %s failed acquire, will retry", name),
						"event", "fleet:lock:acquire_fail")
					break acqLoop
				}

			case <-timeout.C:
				// Consensus process timed out
				lk.release()
				slog.Debug(fmt.Sprintf("[fleet] Lock %s acquire timed out, will retry", name),
					"event", "fleet:lock:acquire_timeout")
				break acqLoop

			case <-ctx.Done():
				// Operation cancelled by context
				lk.release()
				timeout.Stop()
				return nil, ctx.Err()
			}
		}

		// Random backoff before retry to avoid stampedes
		// Wait between 0 and ~65ms
		t := time.NewTimer(time.Duration(rand16()) * time.Microsecond)
		select {
		case <-t.C:
			// Continue with retry
		case <-ctx.Done():
			// Operation cancelled during backoff
			t.Stop()
			return nil, ctx.Err()
		}
	}
}

// finalizeLocalLock is a finalizer function that ensures locks are released
// when garbage collected. This prevents lock leaks if the application forgets
// to call Release().
func finalizeLocalLock(lk *LocalLock) {
	lk.Release()
}

// Release releases a previously acquired lock.
// This method is safe to call multiple times (only the first call has effect).
func (lk *LocalLock) Release() {
	// Use sync.Once to ensure we only release once
	lk.once.Do(func() {
		lk.lk.release()
	})
}

// valid checks if a lock is still valid.
// A lock is valid if it's not failed/released and hasn't timed out.
//
// Returns:
//   - true if the lock is valid, false otherwise
func (lk *globalLock) valid() bool {
	if lk.status == 2 {
		// Status 2 = Failed/Released
		return false
	}
	if time.Until(lk.timeout) < 0 {
		// Lock has timed out
		return false
	}
	return true
}

// handleLockReq processes a lock request from a peer.
// It checks if the requested lock can be granted and responds accordingly.
//
// Parameters:
//   - p: The peer that sent the request
//   - data: The lock request data
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) handleLockReq(p *Peer, data []byte) error {
	// Decode the lock request data
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil // Invalid data, silently ignore
	}

	// Check if we already have this lock
	g := a.getLock(lk)
	if g != nil {
		if g.t == t && g.owner == o {
			// This is the same lock, so approve it
			// (This can happen if the peer is retrying)
			return p.WritePacket(context.Background(), PacketLockRes, append(data, Aye))
		}

		// Different lock with same name, reject the request
		return p.WritePacket(context.Background(), PacketLockRes, append(data, Nay))
	}

	// Try to create the lock locally
	g = a.makeLock(lk, o, t, false)
	if g == nil {
		// Failed to create the lock (race condition?)
		return p.WritePacket(context.Background(), PacketLockRes, append(data, Nay))
	}

	// Set a short timeout for pending confirmation
	g.timeout = time.Now().Add(10 * time.Second)
	g.lk.Unlock() // Unlock the mutex (was locked in makeLock)

	// Approve the lock request
	return p.WritePacket(context.Background(), PacketLockRes, append(data, Aye))
}

// handleLockRes processes a lock response from a peer.
// This is called when a peer responds to our lock request with an aye or nay.
// It tallies the votes and updates the lock status based on the consensus rules.
//
// Parameters:
//   - p: The peer that sent the response
//   - data: The lock response data
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) handleLockRes(p *Peer, data []byte) error {
	// Decode the lock response data
	lk, t, o, data := decodeLockBytes(data)
	if lk == "" || len(data) < 1 {
		return nil // Invalid data, silently ignore
	}

	// Extract the response (Aye or Nay)
	res := data[0]

	// Find the lock this response is for
	g := a.getLock(lk)
	if g == nil {
		// Lock no longer exists locally
		return nil
	}

	// Verify this response is for the right lock
	if g.t != t || g.owner != o {
		// Different timestamp or owner, ignore
		return nil
	}

	// Get peer ID and count for quorum calculations
	id := p.id
	cnt := a.GetPeersCount()

	// Lock the mutex to safely update the aye/nay lists
	g.lk.Lock()
	defer g.lk.Unlock()

	// Check if this peer has already voted
	for _, v := range g.aye {
		if v == id {
			return nil // Already voted aye
		}
	}
	for _, v := range g.nay {
		if v == id {
			return nil // Already voted nay
		}
	}

	// Record the vote
	switch res {
	case Aye:
		g.aye = append(g.aye, id)
	case Nay:
		g.nay = append(g.nay, id)
	}

	// If the lock status is no longer pending, we're done
	if g.getStatus() != 0 {
		return nil
	}

	// Special rules for a 2-node fleet (this node + 1 peer)
	if cnt == 2 {
		if uint32(len(g.aye)) >= 1 {
			// With 2 nodes, a single aye confirms the lock
			g.setStatus(1) // Confirmed
			return nil
		}
		if uint32(len(g.nay)) >= 1 {
			// With 2 nodes, a single nay rejects the lock
			g.setStatus(2) // Failed
			return nil
		}
		return nil
	}

	// Normal consensus rules for 3+ nodes
	if uint32(len(g.aye)) >= ((cnt / 2) + 1) {
		// Majority confirmation rule: more than half of the nodes approve
		g.setStatus(1) // Confirmed
		return nil
	}
	if uint32(len(g.nay)) >= ((cnt / 3) + 1) {
		// Rejection rule: more than a third of the nodes reject
		g.setStatus(2) // Failed
		return nil
	}

	// Not enough votes yet, keep waiting
	return nil
}

// handleLockConfirm processes a lock confirmation message from a peer.
// This is called when a peer has achieved consensus for a lock and is notifying
// all nodes to confirm it with a longer timeout.
//
// Parameters:
//   - p: The peer that sent the confirmation
//   - data: The lock confirmation data
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) handleLockConfirm(p *Peer, data []byte) error {
	// Decode the lock data
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil // Invalid data, silently ignore
	}

	// Check if we already have this lock
	g := a.getLock(lk)
	if g != nil && g.t == t && g.owner == o {
		// We have the lock, just extend its timeout
		g.timeout = time.Now().Add(30 * time.Minute)
		return nil
	}

	// We don't have this lock yet, create it as confirmed
	g = a.makeLock(lk, o, t, true) // Force creation even if existing lock
	g.timeout = time.Now().Add(30 * time.Minute)
	g.setStatus(1) // Set as confirmed immediately
	g.lk.Unlock()  // Unlock the mutex (was locked in makeLock)
	return nil
}

// handleLockRelease processes a lock release message from a peer.
// This is called when a peer is releasing a lock it previously held.
//
// Parameters:
//   - p: The peer that sent the release message
//   - data: The lock release data
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) handleLockRelease(p *Peer, data []byte) error {
	// Decode the lock data
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil // Invalid data, silently ignore
	}

	// Find the lock
	g := a.getLock(lk)
	if g == nil {
		return nil // Lock doesn't exist locally
	}

	// Verify this is the right lock
	if g.owner != o || g.t != t {
		return nil // Different lock with same name
	}

	// Mark as released and clean up
	g.setStatus(2) // Failed/Released
	g.release()
	return nil
}

// getStatus atomically reads the lock status.
// This is thread-safe and can be called without holding the mutex.
//
// Returns:
//   - The current lock status (0=pending, 1=confirmed, 2=failed/released)
func (lk *globalLock) getStatus() uint32 {
	return atomic.LoadUint32(&lk.status)
}

// setStatus atomically updates the lock status to a higher value.
// This is thread-safe and can be called without holding the mutex.
// The status can only increase, never decrease (0→1→2).
//
// Parameters:
//   - v: The new status value to set
func (lk *globalLock) setStatus(v uint32) {
	for {
		oldv := lk.getStatus()
		if oldv >= v {
			// Status can never decrease
			return
		}
		if atomic.CompareAndSwapUint32(&lk.status, oldv, v) {
			break
		}
		// CAS failed, retry with current value
	}

	// Notify waiters about the status change
	select {
	case lk.ch <- v:
		// Successfully sent notification
	default:
		// Channel buffer is full, skip notification
		// This is okay because we only need one notification to wake up waiters
	}
}
