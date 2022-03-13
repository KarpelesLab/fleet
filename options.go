package fleet

import "net"

type AgentOption interface {
	apply(*Agent)
}

func (f GetFileFunc) apply(a *Agent) {
	a.GetFile = f
}

type OptionPort int

func (f OptionPort) apply(a *Agent) {
	a.port = int(f)
}

type OptionListener struct {
	net.Listener
}

func (o OptionListener) apply(a *Agent) {
	a.socket = o.Listener
}
