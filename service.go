package fleet

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// embed connection in a separate object to avoid confusing go's HTTP server (among other shit)
type ServiceConn struct {
	net.Conn
}

func (a *AgentObj) RoundTripper() http.RoundTripper {
	return a.transport
}

func (a *AgentObj) DialContext(c context.Context, network, addr string) (net.Conn, error) {
	return a.Dial(network, addr)
}

func (a *AgentObj) Dial(network, addr string) (net.Conn, error) {
	// addr is in the form of <service>.<id>:<irrelevant port>

	addr, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrSplit := strings.Split(addr, ".")
	if len(addrSplit) != 2 {
		return nil, errors.New("could not parse host")
	}

	id, err := uuid.Parse(addrSplit[1])
	if err != nil {
		p := a.GetPeerByName(addrSplit[1])
		if p != nil {
			id = p.id
		} else {
			return nil, err
		}
	}

	return a.Connect(id, addrSplit[0])
}

// connect to given peer under specified protocol (if supported)
func (a *AgentObj) Connect(id uuid.UUID, service string) (net.Conn, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("no route to peer")
	}

	service_b := []byte(service)
	if len(service_b) > 255 {
		return nil, errors.New("service name too long")
	}

	cfg := a.outCfg.Clone()
	cfg.ServerName = id.String()
	cfg.NextProtos = []string{"p2p"}

	c, err := tls.Dial("tcp", p.addr.IP.String()+":61337", cfg)
	if err != nil {
		log.Printf("[fleet] p2p connect error: %s", err)
		return nil, err
	}

	_, err = c.Write(append([]byte{byte(len(service_b))}, service_b...))
	if err != nil {
		log.Printf("[fleet] p2p failed to write service request: %s", err)
		c.Close()
		return nil, err
	}

	res := make([]byte, 1)
	_, err = io.ReadFull(c, res)

	if err != nil {
		log.Printf("[fleet] p2p failed to get protocol response: %s", err)
		c.Close()
		return nil, err
	}

	if res[0] > 0 {
		res = make([]byte, res[0])
		_, err := io.ReadFull(c, res)
		if err != nil {
			log.Printf("[fleet] p2p failed to get protocol error: %s", err)
			c.Close()
			return nil, err
		}
		c.Close()
		log.Printf("[fleet] p2p failed with remote error: %s", res)
		return nil, errors.New(string(res))
	}

	// success
	return &ServiceConn{Conn: c}, nil
}

func (a *AgentObj) AddService(service string) chan net.Conn {
	a.services[service] = make(chan net.Conn)

	return a.services[service]
}

func (a *AgentObj) handleServiceConn(tc *tls.Conn) {
	res := make([]byte, 1)
	_, err := io.ReadFull(tc, res)
	if err != nil {
		log.Printf("[fleet] incoming p2p link: failed to get service name length")
		tc.Close()
		return
	}

	if res[0] == 0 {
		// ???
		log.Printf("[fleet] incoming p2p link: failed to get service name (zero length)")
		tc.Close()
		return
	}

	res = make([]byte, res[0])

	_, err = io.ReadFull(tc, res)
	if err != nil {
		log.Printf("[fleet] incoming p2p link: failed to get service name: %s", err)
		tc.Close()
		return
	}

	a.forwardConnection(string(res), tc)
}

func (a *AgentObj) forwardConnection(service string, c net.Conn) {
	ch, ok := a.services[service]
	if !ok {
		err := []byte("no such service")
		c.Write(append([]byte{byte(len(err))}, err...))
		log.Printf("[fleet] p2p connection to service %s rejected (no such service)", service)
		c.Close()
		return
	}

	// signal success
	_, err := c.Write([]byte{0})
	if err != nil {
		log.Printf("[fleet] p2p connection failed to notify success: %s", err)
	}

	ch <- &ServiceConn{Conn: c}
}
