// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

// AgentOption defines the interface for options that can be passed to the
// New() function when creating a new Agent. This follows the functional
// options pattern, allowing flexible configuration of agents.
//
// To implement a new option type, create a type that has an apply(*Agent)
// method, which will be called during agent initialization.
type AgentOption interface {
	// apply configures the provided agent with this option
	apply(*Agent)
}

// Implementation of the AgentOption interface for GetFileFunc
// This allows GetFileFunc to be passed directly as an option to New()
func (f GetFileFunc) apply(a *Agent) {
	a.GetFile = f
}
