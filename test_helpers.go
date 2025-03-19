// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

// TestOption defines an AgentOption that can be used for testing purposes.
// This allows easier agent configuration in tests without modifying the
// main codebase.
type TestOption struct {
	fn func(*Agent)
}

// apply implements the AgentOption interface for TestOption
func (o TestOption) apply(a *Agent) {
	o.fn(a)
}

// WithName returns an AgentOption that sets the agent's name
func WithName(name string) AgentOption {
	return TestOption{
		fn: func(a *Agent) {
			a.name = name
		},
	}
}

// WithDivision returns an AgentOption that sets the agent's division
func WithDivision(division string) AgentOption {
	return TestOption{
		fn: func(a *Agent) {
			a.division = division
		},
	}
}

// WithID returns an AgentOption that sets the agent's ID
func WithID(id string) AgentOption {
	return TestOption{
		fn: func(a *Agent) {
			a.id = id
		},
	}
}
