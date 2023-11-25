package fleet

import "sync"

var (
	self     *Agent
	selfLk   sync.RWMutex
	selfCond = sync.NewCond(selfLk.RLocker())
)

// Self returns the Agent instance returned by New() (or similar), and will
// wait if instance has not been instanciated yet. As such, Self() should not
// be used in func init(), but only in separate goroutines or after instance
// has been created.
func Self() *Agent {
	selfLk.RLock()
	defer selfLk.RUnlock()
	for {
		if self != nil {
			return self
		}
		selfCond.Wait()
	}
}

func selfNoWait() *Agent {
	selfLk.RLock()
	defer selfLk.RUnlock()
	return self
}

func setSelf(a *Agent) {
	selfLk.Lock()
	defer selfLk.Unlock()

	if self == nil {
		self = a
	}
	selfCond.Broadcast()
}

// IsReady returns true if the fleet is initiated and configured properly
func IsReady() bool {
	a := selfNoWait()

	if a == nil {
		return false
	}
	return a.GetStatus() == 1
}
