package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/KarpelesLab/spotlib"
	"github.com/quic-go/quic-go"
)

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

type quicBundle struct {
	quic.Stream
	c quic.Connection
}

func (b *quicBundle) Close() error {
	// close both stream and connection
	b.Stream.Close()
	b.c.CloseWithError(0, "")
	return nil
}

func (b *quicBundle) LocalAddr() net.Addr {
	return b.c.LocalAddr()
}

func (b *quicBundle) RemoteAddr() net.Addr {
	return b.c.RemoteAddr()
}

// connect to given peer under specified protocol (if supported)
func (a *Agent) Connect(id string, service string) (net.Conn, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("no route to peer")
	}

	cfg := a.outCfg.Clone()
	cfg.ServerName = id
	//cfg.NextProtos = []string{"p2p"}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := a.quicT.Dial(ctx, spotlib.SpotAddr(p.id+"/"+service), cfg, nil)
	if err != nil {
		return nil, err
	}
	conn, err := res.OpenStreamSync(ctx)
	if err != nil {
		res.CloseWithError(0, "")
		return nil, err
	}

	return &quicBundle{Stream: conn, c: res}, nil
}

func (a *Agent) AddService(service string) chan net.Conn {
	a.svcMutex.Lock()
	defer a.svcMutex.Unlock()

	a.services[service] = make(chan net.Conn)

	return a.services[service]
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
