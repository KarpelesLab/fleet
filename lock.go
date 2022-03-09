package fleet

import (
	"context"
	"errors"
	"sync"
	"time"
)

type LocalLock struct {
	name    string
	t       uint64
	aye     []string     // peers ids approving lock
	nay     []string     // peers ids rejecting lock
	lk      sync.RWMutex // for aye/nay updates
	cd      *sync.Cond   // used when acquiring loco
	release sync.Once    // used to ensure release is called only once
	timeout time.Time
}

type globalLock struct {
	name   string
	t      uint64
	owner  string        // owner node
	ch     chan struct{} // wait channel for lock release
	status int           // 0=new 1=confirmed
	a      *Agent
}

func (a *Agent) getLock(name string) *globalLock {
	a.globalLocksLk.RLock()
	defer a.globalLocksLk.RUnlock()
	v, ok := a.globalLocks[name]
	if ok {
		return v
	}
	return nil
}

func (a *Agent) makeLock(name, owner string, tm uint64) *globalLock {
	a.globalLocksLk.Lock()
	defer a.globalLocksLk.Unlock()

	if _, ok := a.globalLocks[name]; ok {
		return nil
	}

	lk := &globalLock{
		name:  name,
		owner: owner,
		t:     tm,
		ch:    make(chan struct{}),
		a:     a,
	}
	a.globalLocks[name] = lk
	return lk
}

func (l *globalLock) release() {
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

func (a *Agent) Lock(ctx context.Context, name string) (*LocalLock, error) {
	// Lock function attempts to grab a lock and get it confirmed globally
	// if >= (1/2+1) of nodes respond aye, the lock is confirmed and this function returns
	// if >= (1/3+1) of nodes respond nay, lock acquire fails and is retried unless ctx timeouts

	// first, let's check if this isn't already locked, if it is, wait
	for {
		lk := a.getLock(name)

		if lk != nil {
			select {
			case <-lk.ch:
				// ok
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}

		// let's catch a lock
		now := time.Now()
		tm := uint64(now.Unix()) * 1000000
		tm += uint64(now.Nanosecond()) / 1000 // convert to microsecond

		lk = a.makeLock(name, a.id, tm)
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

		newlk := &LocalLock{
			name: name,
			t:    tm,
		}
		newlk.cd = sync.NewCond(newlk.lk.RLocker())
		// returned locallock object will have a finalizer setup, but calling release manually is preferred
		return nil, errors.New("TODO")
	}
}
