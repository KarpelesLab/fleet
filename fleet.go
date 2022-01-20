package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand"
	"net"
	"net/http"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/KarpelesLab/jwt"
)

var (
	Agent = &AgentObj{
		id:       "local",
		name:     "local",
		peers:    make(map[string]*Peer),
		services: make(map[string]chan net.Conn),
		rpc:      make(map[uintptr]chan *PacketRpcResponse),
	}
	rpcE map[string]RpcEndpoint
)

type AgentObj struct {
	socket net.Listener

	id       string
	name     string
	division string
	hostname string // only the hostname side

	inCfg  *tls.Config
	outCfg *tls.Config
	ca     *x509.CertPool
	cert   tls.Certificate

	announceIdx uint64

	peers      map[string]*Peer
	peersMutex sync.RWMutex

	services  map[string]chan net.Conn
	svcMutex  sync.RWMutex
	transport http.RoundTripper

	rpc  map[uintptr]chan *PacketRpcResponse
	rpcL sync.RWMutex
}

func initAgent(token *jwt.Token) {
	err := Agent.doInit(token)
	if err != nil {
		log.Printf("[agent] failed to init agent: %s", err)
	}
}

func (a *AgentObj) doInit(token *jwt.Token) (err error) {
	if token != nil {
		// update info based on jwt data
		if id := token.Payload().GetString("id"); id != "" {
			a.id = id
		}
		if name := token.Payload().GetString("nam"); name != "" {
			a.name = name
		}
		if div := token.Payload().GetString("loc"); div != "" {
			a.division = div
		}
		if iss := token.Payload().GetString("iss"); iss != "" {
			a.hostname = iss
		}
	}

	a.cert, err = GetInternalCert()
	if err != nil {
		return
	}

	// load CA
	a.ca, _ = GetCA()

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

	go a.listenLoop()
	go a.eventLoop()

	return
}

func (a *AgentObj) Id() string {
	return a.id
}

func (a *AgentObj) Name() (string, string) {
	return a.name, a.hostname
}

func SetRpcEndpoint(e string, f RpcEndpoint) {
	if rpcE == nil {
		rpcE = make(map[string]RpcEndpoint)
	}
	rpcE[e] = f
}

// func(interface{}) (interface{}, error)
func TriggerRpcEndpoint(e string, p interface{}) (interface{}, error) {
	if rpcE == nil {
		return nil, fs.ErrNotExist
	}
	ep, ok := rpcE[e]
	if !ok {
		return nil, fs.ErrNotExist
	}

	return ep(p)
}

func (a *AgentObj) BroadcastRpc(endpoint string, data interface{}) error {
	// send request
	pkt := &PacketRpc{
		SourceId: a.id,
		Endpoint: endpoint,
		Data:     data,
	}

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return nil
	}

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt2 := &PacketRpc{}
		*pkt2 = *pkt
		pkt2.TargetId = p.id
		go p.Send(pkt2)
	}

	return nil
}

func (a *AgentObj) broadcastDbRecord(bucket, key, val []byte, v DbStamp) error {
	pkt := &PacketDbRecord{
		SourceId: a.id,
		Stamp:    v,
		Bucket:   bucket,
		Key:      key,
		Val:      val,
	}

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return nil
	}

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt2 := &PacketDbRecord{}
		*pkt2 = *pkt
		pkt2.TargetId = p.id
		go p.Send(pkt2)
	}

	return nil
}

type rpcChoiceStruct struct {
	routines uint32
	peer     *Peer
}

func (a *AgentObj) AnyRpc(division string, endpoint string, data interface{}) error {
	// send request
	pkt := &PacketRpc{
		SourceId: a.id,
		Endpoint: endpoint,
		Data:     data,
	}

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return errors.New("no peer available")
	}

	var choices []rpcChoiceStruct

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		if division != "" && p.division != division {
			continue
		}
		choices = append(choices, rpcChoiceStruct{routines: p.numG, peer: p})
	}

	sort.SliceStable(choices, func(i, j int) bool { return choices[i].routines < choices[j].routines })

	for _, i := range choices {
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt.TargetId = i.peer.id
		atomic.AddUint32(&i.peer.numG, 1) // increment value to avoid sending bursts to the same node
		go i.peer.Send(pkt)
		return nil
	}

	return errors.New("no peer available")
}

func (a *AgentObj) DivisionRpc(division int, endpoint string, data interface{}) error {
	divMatch := a.division
	if division > 0 {
		// only keep the N first parts of divison. Eg if N=2 and "divMatch" is "a/b/c", divMatch should become "a/b/"
		pos := 0
		for i := 0; i < division; i += 1 {
			Xpos := strings.IndexByte(divMatch[pos+1:], '/')
			if Xpos == -1 {
				// do exact match
				pos = -1
				break
			}
			pos += Xpos + 1
		}
		if pos > 0 {
			divMatch = divMatch[:pos+1]
		}
	} else if division < 0 {
		// only remove N last parts of division. If N=-1, "a/b/c" becomes "a/b/"
		pos := len(divMatch)
		for i := 0; i < 0-division; i += 1 {
			if pos <= 1 {
				// out of match, just go wildcard
				pos = -1
				break
			}
			Xpos := strings.LastIndexByte(divMatch[:pos-1], '/')
			if Xpos == -1 {
				// wildcard
				pos = -1
				break
			}
			pos = Xpos
		}
		if pos > 0 {
			divMatch = divMatch[:pos]
		} else {
			// wildcard match
			divMatch = ""
		}
	}

	return a.DivisionPrefixRpc(divMatch, endpoint, data)
}

func (a *AgentObj) DivisionPrefixRpc(divMatch string, endpoint string, data interface{}) error {
	// send request
	pkt := &PacketRpc{
		SourceId: a.id,
		Endpoint: endpoint,
		Data:     data,
	}

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return nil
	}

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		if !strings.HasPrefix(p.division, divMatch) {
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt2 := &PacketRpc{}
		*pkt2 = *pkt
		pkt2.TargetId = p.id
		go p.Send(pkt2)
	}

	return nil
}

func (a *AgentObj) RPC(id string, endpoint string, data interface{}) (interface{}, error) {
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
	pkt := &PacketRpc{
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

	if rpcE == nil {
		if pkt.R != 0 {
			res.Error = "RPC: endpoint system not enabled (no endpoints)"
			res.HasError = true
			return a.SendTo(res.TargetId, res)
		}
		return nil
	}

	cb := rpcE[pkt.Endpoint]

	if cb == nil {
		if pkt.R != 0 {
			res.Error = "RPC: endpoint not found"
			res.HasError = true
			return a.SendTo(res.TargetId, res)
		}
		return nil
	}

	if pkt.R == 0 {
		// no return
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[fleet] Panic in RPC: %s", r)
				}
			}()

			cb(pkt.Data)
		}()
		return nil
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				res.Error = fmt.Sprintf("RPC Panic: %s", r)
				res.HasError = true
			}
		}()

		var err error
		res.Data, err = cb(pkt.Data)
		if err != nil {
			res.Error = err.Error()
			res.HasError = true
		}
	}()

	return a.SendTo(res.TargetId, res)
}

func (a *AgentObj) dialPeer(host, name string, id string) {
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
	cfg.ServerName = id
	cfg.NextProtos = []string{"fleet"}

	c, err := tls.Dial("tcp", host+":61337", cfg)
	if err != nil {
		log.Printf("[fleet] failed to connect to peer %s(%s): %s", name, id, err)
		return
	}

	a.newConn(c)
}

func (a *AgentObj) IsConnected(id string) bool {
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

	for {
		select {
		case <-announce.C:
			a.doAnnounce()
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
		Id:   a.id,
		Now:  time.Now(),
		Idx:  x,
		AZ:   a.division,
		NumG: uint32(runtime.NumGoroutine()),
	}

	for _, p := range a.peers {
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		go p.Send(pkt)
	}
}

func (a *AgentObj) doBroadcast(pkt Packet, except_id string) {
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

type SortablePeers []*Peer

func (s SortablePeers) Len() int {
	return len(s)
}

func (s SortablePeers) Less(i, j int) bool {
	return s[i].name < s[j].name
}

func (s SortablePeers) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (a *AgentObj) DumpInfo(w io.Writer) {
	fmt.Fprintf(w, "Fleet Agent Information\n")
	fmt.Fprintf(w, "=======================\n\n")
	fmt.Fprintf(w, "Local name: %s\n", a.name)
	fmt.Fprintf(w, "Division:   %s\n", a.division)
	fmt.Fprintf(w, "Local ID:   %s\n", a.id)
	fmt.Fprintf(w, "Seed ID:    %s (seed stamp: %s)\n", SeedId(), seed.ts)
	fmt.Fprintf(w, "\n")

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	t := make(SortablePeers, 0, len(a.peers))

	for _, p := range a.peers {
		t = append(t, p)
	}

	// sort
	sort.Sort(t)

	for _, p := range t {
		fmt.Fprintf(w, "Peer:     %s (%s)\n", p.name, p.id)
		fmt.Fprintf(w, "Division: %s\n", p.division)
		fmt.Fprintf(w, "Endpoint: %s\n", p.c.RemoteAddr())
		fmt.Fprintf(w, "Connected:%s (%s ago)\n", p.cnx, time.Since(p.cnx))
		fmt.Fprintf(w, "Last Ann: %s\n", time.Since(p.annTime))
		fmt.Fprintf(w, "Latency:  %s\n", p.Ping)
		fmt.Fprintf(w, "Routines: %d\n", p.numG)
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "DB keys:\n")
	for _, bk := range []string{"fleet", "global", "app"} {
		var l []string
		if c, err := NewDbCursor([]byte(bk)); err == nil {
			defer c.Close()
			k, _ := c.First()
			for {
				if k == nil {
					break
				}
				l = append(l, string(k))
				k, _ = c.Next()
			}
		}
		fmt.Fprintf(w, "%s: %v\n", bk, l)
	}
}

func (a *AgentObj) GetPeer(id string) *Peer {
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
		//go a.dialPeer(ann.Ip, "", ann.Id)
		return nil
	}

	return p.processAnnounce(ann, fromPeer)
}

func (a *AgentObj) SendTo(target string, pkt interface{}) error {
	p := a.GetPeer(target) // TODO find best route instead of using GetPeer
	if p == nil {
		return errors.New("no route to peer")
	}

	return p.Send(pkt)
}
