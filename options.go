package fleet

type AgentOption interface {
	apply(*Agent)
}

func (f GetFileFunc) apply(a *Agent) {
	a.GetFile = f
}

type FleetPort int

func (f FleetPort) apply(a *Agent) {
	a.port = int(f)
}
