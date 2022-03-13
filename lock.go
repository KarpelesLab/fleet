package fleet

import (
	"context"
	"encoding/binary"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type LocalLock struct {
	lk   *globalLock
	once sync.Once // once is used to ensure release() is done only once
}

type globalLock struct {
	name    string
	t       uint64
	owner   string      // owner node
	ch      chan uint32 // wait channel for lock release or updates
	status  uint32      // 0=new 1=confirmed 2=failed
	local   bool
	lk      sync.Mutex // for aye/nay updates
	aye     []string   // peers ids approving lock (if local)
	nay     []string   // peers ids rejecting lock (if local)
	a       *Agent
	timeout time.Time
}

// load a lock from the db
func (a *Agent) getLock(name string) *globalLock {
	a.globalLocksLk.RLock()
	defer a.globalLocksLk.RUnlock()
	v, ok := a.globalLocks[name]
	if ok && v.valid() {
		return v
	}
	return nil
}

// create a new lock
func (a *Agent) makeLock(name, owner string, tm uint64, force bool) *globalLock {
	a.globalLocksLk.Lock()
	defer a.globalLocksLk.Unlock()

	if v, ok := a.globalLocks[name]; ok {
		if !force && v.valid() {
			return nil
		}
		v.setStatus(2)
		go v.release() // this will lock because we already hold a.globalLocksLk
	}

	lk := &globalLock{
		name:    name,
		owner:   owner,
		t:       tm,
		ch:      make(chan uint32, 1),
		a:       a,
		timeout: time.Now().Add(30 * time.Minute),
	}
	// lock it now
	lk.lk.Lock()
	a.globalLocks[name] = lk
	return lk
}

func (l *globalLock) release() {
	log.Printf("[fleet] releasing lock %s %d %s", l.name, l.t, l.owner)
	if l.local {
		// broadcast release
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		l.a.BroadcastPacket(ctx, PacketLockRelease, l.Key())
	}

	l.a.globalLocksLk.Lock()
	defer l.a.globalLocksLk.Unlock()

	v, ok := l.a.globalLocks[l.name]
	if !ok || v != l {
		// wrong call?
		return
	}
	delete(l.a.globalLocks, l.name)
	close(l.ch)
}

func (l *globalLock) Key() []byte {
	return codeLockBytes(l.name, l.t, l.owner)
}

// generate a []byte of a lock name's stamp and owner
func codeLockBytes(name string, t uint64, owner string) []byte {
	v := make([]byte, 8+2+len(name)+len(owner))
	s := v
	s[0] = byte(len(name))
	copy(s[1:], name)
	s = s[len(name)+1:]
	binary.BigEndian.PutUint64(s[:8], t)
	s = s[8:]
	s[0] = byte(len(owner))
	copy(s[1:], owner)

	return v
}

// reads a []byte containing info and returns data
func decodeLockBytes(v []byte) (string, uint64, string, []byte) {
	// return: name, stamp, owner, and remaining of v

	// check if v is long enough
	if len(v) < 10 {
		return "", 0, "", nil
	}
	nameLen := v[0]
	if len(v) < int(nameLen)+1+8+1 { // nameLen, stamp, ownerLen
		return "", 0, "", nil
	}
	name := v[1 : int(nameLen)+1]
	v = v[int(nameLen)+1:]

	t := binary.BigEndian.Uint64(v[:8])
	v = v[8:]

	ownerLen := v[0]
	if len(v) < int(ownerLen)+1 {
		return "", 0, "", nil
	}
	owner := v[1 : ownerLen+1]
	v = v[ownerLen+1:]

	return string(name), t, string(owner), v
}

func (a *Agent) Lock(ctx context.Context, name string) (*LocalLock, error) {
	// Lock function attempts to grab a lock and get it confirmed globally
	// if >= (1/2+1) of nodes respond aye, the lock is confirmed and this function returns
	// if >= (1/3+1) of nodes respond nay, lock acquire fails and is retried unless ctx timeouts

	if name == "" {
		return nil, ErrInvalidLockName
	}

	log.Printf("[fleet] Attempting to acquire lock %s", name)
	start := time.Now()

	// first, let's check if this isn't already locked, if it is, wait
	for {
		lk := a.getLock(name)

		if lk != nil {
			select {
			case <-lk.ch:
				// something has changed
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		// let's catch a lock
		tm := UniqueTimestamp()

		lk = a.makeLock(name, a.id, tm, false)
		if lk == nil {
			// failed to acquire, retry
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				// do not wait
			}
			continue
		}

		lk.local = true
		lk.lk.Unlock()

		log.Printf("[fleet] Lock %s acquire attempt with t=%d", name, tm)

		if a.GetPeersCount() <= 1 {
			// we can't have global locks with no peers
			lk.setStatus(1)
			res := &LocalLock{lk: lk}
			runtime.SetFinalizer(res, finalizeLocalLock)
			log.Printf("[fleet] Lock %s acquired in %s (no other peers)", name, time.Since(start))
			return res, nil
		}

		// attempt acquire
		timeout := time.NewTimer(5 * time.Second)
		go a.BroadcastPacket(context.Background(), PacketLockReq, lk.Key())

	acqLoop:
		for {
			select {
			case st, ok := <-lk.ch:
				if !ok {
					// lock was cancelled externally
					timeout.Stop()
					return nil, ErrCancelledLock
				}
				if st == 0 {
					// nothing new
					break
				}
				if st == 1 {
					// ready
					res := &LocalLock{lk: lk}
					runtime.SetFinalizer(res, finalizeLocalLock)
					timeout.Stop()
					go a.BroadcastPacket(context.Background(), PacketLockConfirm, lk.Key())
					log.Printf("[fleet] Lock %s acquired in %s", name, time.Since(start))
					return res, nil
				}
				if st == 2 {
					// reached too many nay or another lock confirmed on top of us
					lk.release()
					log.Printf("[fleet] Lock %s failed acquire, will retry", name)
					break acqLoop
				}
			case <-timeout.C:
				// reached timeout
				lk.release()
				log.Printf("[fleet] Lock %s acquire timed out, will retry", name)
				break acqLoop
			case <-ctx.Done():
				lk.release()
				timeout.Stop()
				return nil, ctx.Err()
			}
		}
	}
}

func finalizeLocalLock(lk *LocalLock) {
	lk.Release()
}

func (lk *LocalLock) Release() {
	// perform release
	lk.once.Do(func() {
		lk.lk.release()
	})
}

func (lk *globalLock) valid() bool {
	if lk.status == 2 {
		return false
	}
	if time.Until(lk.timeout) < 0 {
		return false
	}
	return true
}

func (a *Agent) handleLockReq(p *Peer, data []byte) error {
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil
	}
	g := a.getLock(lk)
	if g != nil {
		if g.t == t && g.owner == o {
			// return aye (already obtained)
			return p.WritePacket(context.Background(), PacketLockRes, append(data, Aye))
		}
		// return nay
		log.Printf("[fleet] rejecting request for lock %s by %s:%d because already belonging to %s:%d", lk, o, t, g.owner, g.t)
		return p.WritePacket(context.Background(), PacketLockRes, append(data, Nay))
	}

	// obtain lock
	g = a.makeLock(lk, o, t, false)
	if g == nil {
		// failed → return nay
		log.Printf("[fleet] rejecting request for lock %s because makeLock failed (race condition?)", lk)
		return p.WritePacket(context.Background(), PacketLockRes, append(data, Nay))
	}
	g.timeout = time.Now().Add(10 * time.Second)
	g.lk.Unlock()

	// good → return aye
	return p.WritePacket(context.Background(), PacketLockRes, append(data, Aye))
}

func (a *Agent) handleLockRes(p *Peer, data []byte) error {
	lk, t, o, data := decodeLockBytes(data)
	if lk == "" {
		return nil
	}
	if len(data) < 1 {
		return nil
	}
	res := data[0]
	g := a.getLock(lk)
	if g == nil {
		// can't
		return nil
	}
	if g.t != t || g.owner != o {
		// wrong lock
		return nil
	}

	id := p.id
	cnt := a.GetPeersCount()

	g.lk.Lock()
	defer g.lk.Unlock()

	// check if peer is already in aye or nay
	for _, v := range g.aye {
		if v == id {
			return nil
		}
	}
	for _, v := range g.nay {
		if v == id {
			return nil
		}
	}
	switch res {
	case Aye:
		log.Printf("[fleet] got AYE from %s for %s", id, lk)
		g.aye = append(g.aye, id)
	case Nay:
		log.Printf("[fleet] got NAY from %s for %s", id, lk)
		g.nay = append(g.nay, id)
	}

	if g.getStatus() != 0 {
		return nil
	}

	if cnt < 3 {
		// special rule
		if uint32(len(g.aye)) >= cnt {
			// we got a aye
			g.setStatus(1)
			return nil
		}
		if uint32(len(g.nay)) >= 1 {
			// give up on this
			g.setStatus(2)
			return nil
		}
		return nil
	}

	if uint32(len(g.aye)) >= ((cnt / 2) + 1) {
		// we got a aye
		g.setStatus(1)
		return nil
	}
	if uint32(len(g.nay)) >= ((cnt / 3) + 1) {
		// give up on this
		g.setStatus(2)
		return nil
	}
	return nil
}

func (a *Agent) handleLockConfirm(p *Peer, data []byte) error {
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil
	}
	g := a.getLock(lk)
	if g != nil && g.t == t && g.owner == o {
		g.timeout = time.Now().Add(30 * time.Minute)
		return nil
	}

	// make lock
	g = a.makeLock(lk, o, t, true)
	g.timeout = time.Now().Add(30 * time.Minute)
	g.status = 1
	g.lk.Unlock()
	return nil
}

func (a *Agent) handleLockRelease(p *Peer, data []byte) error {
	lk, t, o, _ := decodeLockBytes(data)
	if lk == "" {
		return nil
	}
	g := a.getLock(lk)
	if g == nil {
		return nil
	}
	if g.owner != o || g.t != t {
		return nil
	}
	g.release()
	return nil
}

func (lk *globalLock) getStatus() uint32 {
	return atomic.LoadUint32(&lk.status)
}

func (lk *globalLock) setStatus(v uint32) {
	if lk.getStatus() == v {
		return
	}
	atomic.StoreUint32(&lk.status, v)
	select {
	case lk.ch <- v:
	default:
	}
}
