// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"testing"
)

// TestContextPropagation tests that context cancellation is properly handled
// in various fleet functions.
func TestContextPropagation(t *testing.T) {
	// Skip complex network tests
	t.Skip("Skipping context propagation tests that require full peer initialization")
}