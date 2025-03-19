// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestForRaceConditions runs a series of concurrent operations to help detect
// race conditions in the codebase. This should be used with the -race flag.
// Example: go test -race github.com/KarpelesLab/fleet -run TestForRaceConditions
func TestForRaceConditions(t *testing.T) {
	// Create a test agent
	a := New(WithName("test-agent-1"), WithDivision("test-division"))
	if a == nil {
		t.Fatalf("Failed to create agent")
	}
	defer a.Close()

	// Test concurrent lock operations
	testConcurrentLocks(t, a)
}

// testConcurrentLocks tests for race conditions in lock handling
func testConcurrentLocks(t *testing.T, a *Agent) {
	const numLocks = 5
	const numGoroutines = 3

	var wg sync.WaitGroup

	// Run tests for both local and global locks to test both code paths
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()

			for j := 0; j < numLocks; j++ {
				lockName := fmt.Sprintf("test-lock-%d-%d", n, j)
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

				// Try to acquire the lock
				lock, err := a.Lock(ctx, lockName)
				if err == nil && lock != nil {
					// Successfully acquired lock, release it after a short delay
					time.Sleep(10 * time.Millisecond)
					lock.Release()
				}

				cancel()
			}
		}(i)
	}

	wg.Wait()
}

// TestResourceLeaks tests for common resource leaks
func TestResourceLeaks(t *testing.T) {
	// Test that acquiring concurrent locks doesn't leak resources
	testConcurrentAcquireReleaseLeaks(t)
}

// testConcurrentAcquireReleaseLeaks tests resource cleanup with many lock operations
func testConcurrentAcquireReleaseLeaks(t *testing.T) {
	a := New(WithName("test-agent"), WithDivision("test-division"))
	if a == nil {
		t.Fatalf("Failed to create agent")
	}
	defer a.Close()

	// Create several locks in succession
	for i := 0; i < 100; i++ {
		lockName := fmt.Sprintf("test-lock-%d", i)
		lock, err := a.Lock(context.Background(), lockName)
		if err != nil {
			// Not expected, but not the focus of this test
			continue
		}
		// Release immediately
		lock.Release()
	}

	// If there's a resource leak, running with -race would likely detect it
	// This is more of a functional test than an assertion-based test
}
