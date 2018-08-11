package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/google/uuid"
)

var Agent *AgentObj

type AgentObj struct {
	socket net.Listener

	id   uuid.UUID
	name string

	inCfg  *tls.Config
	outCfg *tls.Config
	ca     *x509.CertPool
	cert   tls.Certificate

	announceIdx uint64

	peers      map[uuid.UUID]*Peer
	peersMutex *sync.RWMutex

	self JsonFleetHostInfo

	services  map[string]chan net.Conn
	transport http.RoundTripper

	rpc  map[uintptr]chan *PacketRpcResponse
	rpcE map[string]RpcEndpoint
	rpcL sync.RWMutex
}

func initAgent() {
	Agent = new(AgentObj)

	err := Agent.doInit()
	if err != nil {
		log.Printf("[agent] failed to init agent: %s", err)
	}
}

func (a *AgentObj) doInit() (err error) {
	a.peers = make(map[uuid.UUID]*Peer)
	a.peersMutex = new(sync.RWMutex)
	a.services = make(map[string]chan net.Conn)
	a.rpc = make(map[uintptr]chan *PacketRpcResponse)

	a.name = "local"

	// load fleet info
	fleet_info, err := ioutil.ReadFile("fleet.json")
	if err != nil {
		return
	}
	// parse json
	err = json.Unmarshal(fleet_info, &a.self)
	if err != nil {
		return
	}

	a.id, err = uuid.Parse(a.self.Id)
	if err != nil {
		return
	}
	a.name = a.self.Name

	a.cert, err = tls.LoadX509KeyPair("internal_key.pem", "internal_key.key")
	if err != nil {
		return
	}

	// load CA
	ca_data, err := ioutil.ReadFile("internal_ca.pem")
	if err != nil {
		return
	}

	a.ca = x509.NewCertPool()
	a.ca.AppendCertsFromPEM(ca_data)

	// create tls.Config objects
	a.inCfg = new(tls.Config)
	a.outCfg = new(tls.Config)

	// set certificates
	a.inCfg.Certificates = []tls.Certificate{a.cert}
	a.outCfg.Certificates = []tls.Certificate{a.cert}
	a.inCfg.RootCAs = a.ca
	a.outCfg.RootCAs = a.ca

	a.inCfg.NextProtos = []string{"fleet", "p2p"}

	// configure client auth
	a.inCfg.ClientAuth = tls.RequireAndVerifyClientCert
	a.inCfg.ClientCAs = a.ca

	a.socket, err = tls.Listen("tcp", ":61337", a.inCfg)
	log.Printf("[agent] Listening on :61337")

	// create a transport object for http queries
	a.transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           a.DialContext,
		DialTLS:               a.Dial,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	a.connectHosts()

	go a.listenLoop()
	go a.eventLoop()

	return
}

func (a *AgentObj) Id() uuid.UUID {
	return a.id
}

func (a *AgentObj) connectHosts() {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	for _, h := range a.self.Hosts {
		id, err := uuid.Parse(h.Id)
		if err != nil {
			log.Printf("[fleet] failed to parse uuid for host")
			continue
		}
		if id == a.id {
			continue
		}
		// check if already connected
		if _, ok := a.peers[id]; ok {
			continue
		}

		go a.dialPeer(h.Name+"."+a.self.Fleet.Hostname, h.Name, id)
	}
}

func (a *AgentObj) SetEndpoint(e string, f RpcEndpoint) {
	a.rpcE[e] = f
}

func (a *AgentObj) RPC(id uuid.UUID, endpoint string, data interface{}) (interface{}, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("Failed to find peer")
	}

	res := make(chan *PacketRpcResponse)
	resId := uintptr(unsafe.Pointer(&res))
	a.rpcL.Lock()
	a.rpc[resId] = res
	a.rpcL.Unlock()

	// send request
	pkt := PacketRpc{
		TargetId: id,
		SourceId: a.id,
		R:        resId,
		Endpoint: endpoint,
		Data:     data,
	}

	p.Send(pkt)

	// get response
	r := <-res

	a.rpcL.Lock()
	delete(a.rpc, resId)
	a.rpcL.Unlock()

	if r == nil {
		return nil, errors.New("failed to wait for response")
	}

	err := error(nil)
	if r.HasError {
		err = errors.New(r.Error)
	}

	return r.Data, err
}

func (a *AgentObj) handleRpc(pkt *PacketRpc) error {
	res := PacketRpcResponse{
		SourceId: a.id,
		TargetId: pkt.SourceId,
		R:        pkt.R,
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				res.Error = fmt.Sprintf("RPC Panic: %s", r)
				res.HasError = true
			}
		}()

		var err error
		res.Data, err = a.rpcE[pkt.Endpoint](pkt.Data)
		if err != nil {
			res.Error = err.Error()
			res.HasError = true
		}
	}()

	return a.SendTo(res.TargetId, res)
}

func (a *AgentObj) dialPeer(host, name string, id uuid.UUID) {
	if id == a.id {
		// avoid connect to self
		return
	}

	// random delay before connect
	time.Sleep(time.Duration(rand.Intn(1500)+2000) * time.Millisecond)

	// check if already connected
	if a.IsConnected(id) {
		return
	}

	cfg := a.outCfg.Clone()
	cfg.ServerName = id.String()
	cfg.NextProtos = []string{"fleet"}

	c, err := tls.Dial("tcp", host+":61337", cfg)
	if err != nil {
		log.Printf("[fleet] failed to connect to peer %s(%s): %s", name, id, err)
		return
	}

	a.newConn(c)
}

func (a *AgentObj) IsConnected(id uuid.UUID) bool {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	_, ok := a.peers[id]
	return ok
}

func (a *AgentObj) listenLoop() {
	for {
		conn, err := a.socket.Accept()
		if err != nil {
			log.Printf("[fleet] failed to accept connections: %s", err)
			return
		}

		go a.newConn(conn)
	}
}

func (a *AgentObj) eventLoop() {
	announce := time.NewTicker(5 * time.Second)
	peerConnect := time.NewTicker(5 * time.Minute)

	for {
		select {
		case <-announce.C:
			a.doAnnounce()
		case <-peerConnect.C:
			a.connectHosts()
		}
	}
}

func (a *AgentObj) doAnnounce() {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return
	}

	x := atomic.AddUint64(&a.announceIdx, 1)

	pkt := &PacketAnnounce{
		Id:  a.id,
		Now: time.Now(),
		Idx: x,
		Ip:  a.self.Ip,
		AZ:  a.self.AZ,
	}

	for _, p := range a.peers {
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		go p.Send(pkt)
	}
}

func (a *AgentObj) doBroadcast(pkt Packet, except_id uuid.UUID) {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return
	}

	for _, p := range a.peers {
		if p.id == except_id {
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		go p.Send(pkt)
	}
}

func (a *AgentObj) DumpInfo(w io.Writer) {
	fmt.Fprintf(w, "Fleet Agent Information\n")
	fmt.Fprintf(w, "=======================\n\n")
	fmt.Fprintf(w, "Local name: %s\n", a.name)
	fmt.Fprintf(w, "Local ID:   %s\n", a.id)
	fmt.Fprintf(w, "Seed ID:    %s (seed stamp: %s)\n", SeedId(), seed.ts)
	fmt.Fprintf(w, "\n")

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	for _, p := range a.peers {
		fmt.Fprintf(w, "Peer:     %s (%s)\n", p.name, p.id)
		fmt.Fprintf(w, "Endpoint: %s\n", p.c.RemoteAddr())
		fmt.Fprintf(w, "Connected:%s (%s ago)\n", p.cnx, time.Since(p.cnx))
		fmt.Fprintf(w, "Last Ann: %s\n", time.Since(p.annTime))
		fmt.Fprintf(w, "Latency:  %s\n", p.Ping)
		fmt.Fprintf(w, "\n")
	}
}

func (a *AgentObj) GetPeer(id uuid.UUID) *Peer {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	return a.peers[id]
}

func (a *AgentObj) GetPeerByName(name string) *Peer {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	for _, p := range a.peers {
		if p.name == name {
			return p
		}
	}

	return nil
}

func (a *AgentObj) handleAnnounce(ann *PacketAnnounce, fromPeer *Peer) error {
	p := a.GetPeer(ann.Id)

	if p == nil {
		// need to establish link
		go a.dialPeer(ann.Ip, "", ann.Id)
		return nil
	}

	return p.processAnnounce(ann, fromPeer)
}

func (a *AgentObj) SendTo(target uuid.UUID, pkt interface{}) error {
	p := a.GetPeer(target) // TODO find best route instead of using GetPeer
	if p == nil {
		return errors.New("no route to peer")
	}

	return p.Send(pkt)
}
