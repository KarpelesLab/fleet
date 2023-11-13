package fleet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// embed connection in a separate object to avoid confusing go's HTTP server (among other stuff)
type ServiceConn struct {
	net.Conn
}

func (a *Agent) RoundTripper() http.RoundTripper {
	return a.transport
}

func (a *Agent) DialContext(c context.Context, network, addr string) (net.Conn, error) {
	return a.Dial(network, addr)
}

func (a *Agent) Dial(network, addr string) (net.Conn, error) {
	// addr is in the form of <service>.<id>:<irrelevant port>

	addr, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrSplit := strings.Split(addr, ".")
	if len(addrSplit) != 2 {
		return nil, errors.New("could not parse host")
	}

	id := addrSplit[1]
	if _, ok := a.peers[id]; !ok {
		p := a.GetPeerByName(addrSplit[1])
		if p != nil {
			id = p.id
		} else {
			return nil, fmt.Errorf("peer not found: %s", addrSplit[1])
		}
	}

	return a.Connect(id, addrSplit[0])
}

// connect to given peer under specified protocol (if supported)
func (a *Agent) Connect(id string, service string) (net.Conn, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("no route to peer")
	}

	if p.ssh != nil {
		ch, reqs, err := p.ssh.OpenChannel("p2p", []byte(service+"."+id))
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(reqs)
		return &quasiConn{Channel: ch, p: p}, nil
	}

	service_b := []byte(service)
	if len(service_b) > 255 {
		return nil, errors.New("service name too long")
	}

	cfg := a.outCfg.Clone()
	cfg.ServerName = id
	cfg.NextProtos = []string{"p2p"}

	c, err := tls.Dial("tcp", p.addr.IP.String()+":"+strconv.FormatInt(int64(a.port), 10), cfg)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] p2p connect error: %s", err), "event", "fleet:service:connect_fail")
		return nil, err
	}

	_, err = c.Write(append([]byte{byte(len(service_b))}, service_b...))
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] p2p failed to write service request: %s", err), "event", "fleet:service:write_fail")
		c.Close()
		return nil, err
	}

	res := make([]byte, 1)
	_, err = io.ReadFull(c, res)

	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] p2p failed to get protocol response: %s", err), "event", "fleet:service:proto_fail")
		c.Close()
		return nil, err
	}

	if res[0] > 0 {
		res = make([]byte, res[0])
		_, err := io.ReadFull(c, res)
		if err != nil {
			slog.Error(fmt.Sprintf("[fleet] p2p failed to get protocol error: %s", err), "event", "fleet:service:get_fail")
			c.Close()
			return nil, err
		}
		c.Close()
		slog.Error(fmt.Sprintf("[fleet] p2p failed with remote error: %s", res), "event", "fleet:service:remote_error")
		return nil, errors.New(string(res))
	}

	// success
	return &ServiceConn{Conn: c}, nil
}

func (a *Agent) AddService(service string) chan net.Conn {
	a.svcMutex.Lock()
	defer a.svcMutex.Unlock()

	a.services[service] = make(chan net.Conn)

	return a.services[service]
}

func (a *Agent) handleServiceConn(tc *tls.Conn) {
	res := make([]byte, 1)
	_, err := io.ReadFull(tc, res)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] incoming p2p link: failed to get service name length"), "event", "fleet:service:name_len_fail")
		tc.Close()
		return
	}

	if res[0] == 0 {
		// ???
		slog.Error(fmt.Sprintf("[fleet] incoming p2p link: failed to get service name (zero length)"), "event", "fleet:service:name_zero_len")
		tc.Close()
		return
	}

	res = make([]byte, res[0])

	_, err = io.ReadFull(tc, res)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] incoming p2p link: failed to get service name: %s", err), "event", "fleet:service:name_read_fail")
		tc.Close()
		return
	}

	a.forwardConnection(string(res), tc)
}

func (a *Agent) forwardConnection(service string, c net.Conn) {
	a.svcMutex.RLock()
	defer a.svcMutex.RUnlock()

	ch, ok := a.services[service]
	if !ok {
		err := []byte("no such service")
		c.Write(append([]byte{byte(len(err))}, err...))
		slog.Error(fmt.Sprintf("[fleet] p2p connection to service %s rejected (no such service)", service), "event", "fleet:service:notfound")
		c.Close()
		return
	}

	// signal success
	_, err := c.Write([]byte{0})
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] p2p connection failed to notify success: %s", err), "event", "fleet:service:success_notify_fail")
	}

	ch <- &ServiceConn{Conn: c}
}

func (a *Agent) getService(service string) chan net.Conn {
	a.svcMutex.RLock()
	defer a.svcMutex.RUnlock()

	ch, ok := a.services[service]
	if !ok {
		return nil
	}

	return ch
}
