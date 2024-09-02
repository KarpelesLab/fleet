package fleet

type AgentOption interface {
	apply(*Agent)
}

func (f GetFileFunc) apply(a *Agent) {
	a.GetFile = f
}
