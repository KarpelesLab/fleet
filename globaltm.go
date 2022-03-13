package fleet

import (
	"sync/atomic"
	"time"
)

var globalTimestampValue uint64

// UniqueTimestamp returns a uint64 timestamp in microsecond that is unique,
// that is even if called multiple times in the same millisecond each call will
// return a different value.
//
// This can be safely called from multiple threads, it does not lock.
func UniqueTimestamp() uint64 {
	now := time.Now()
	tm := uint64(now.Unix()) * 1000000
	tm += uint64(now.Nanosecond()) / 1000 // convert to microsecond

	v := atomic.LoadUint64(&globalTimestampValue)
	if v >= tm {
		// we are generating too many values or timestamp went back,
		// either way we can't use the timestamp, so increase
		// globalTimestampValue instead
		return atomic.AddUint64(&globalTimestampValue, 1) // returns globalTimestampValue+1
	}

	// store timestamp value since it was higher than the current value
	if atomic.CompareAndSwapUint64(&globalTimestampValue, v, tm) {
		// swap successful, now let's just return tm
		return tm
	}

	// compare and swap failed, means globalTimestampValue was updated between load and CaS, let's just return value+1
	return atomic.AddUint64(&globalTimestampValue, 1)
}
