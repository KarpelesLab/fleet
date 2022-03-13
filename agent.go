package fleet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/KarpelesLab/jwt"
	"github.com/KarpelesLab/ringbuf"
	bolt "go.etcd.io/bbolt"
)

type GetFileFunc func(*Agent, string) ([]byte, error)

type Agent struct {
	socket net.Listener

	id       string
	name     string
	division string
	hostname string // only the hostname side
	IP       string // ip as seen from outside
	cache    string // location of cache

	inCfg  *tls.Config
	outCfg *tls.Config
	ca     *x509.CertPool
	cert   tls.Certificate

	announceIdx uint64

	peers      map[string]*Peer
	peersMutex sync.RWMutex
	peersCount int
	port       int // default 61337

	services  map[string]chan net.Conn
	svcMutex  sync.RWMutex
	transport http.RoundTripper

	rpc  map[uintptr]chan *PacketRpcResponse
	rpcL sync.RWMutex

	// log
	logbuf *ringbuf.Writer

	// DB
	db          *bolt.DB
	dbWatch     map[string]DbWatchCallback
	dbWatchLock sync.RWMutex

	// Meta-info
	meta   map[string]interface{}
	metaLk sync.RWMutex

	// getfile callback
	GetFile GetFileFunc

	// seed: use a pointer for atomic seed details update
	seed *seedData

	// locking
	globalLocks   map[string]*globalLock
	globalLocksLk sync.RWMutex
}

// New will just initialize a basic agent without any settings
func New(opts ...AgentOption) *Agent {
	a := spawn()
	a.port = 61337
	for _, o := range opts {
		o.apply(a)
	}
	a.start()
	return a
}

// return a new agent using the provided GetFile method
func WithGetFile(f GetFileFunc) *Agent {
	return New(f)
}

func spawn() *Agent {
	local := "local"
	if host, err := os.Hostname(); err == nil && host != "" {
		local = host
	}

	a := &Agent{
		id:          local,
		name:        local,
		peers:       make(map[string]*Peer),
		services:    make(map[string]chan net.Conn),
		rpc:         make(map[uintptr]chan *PacketRpcResponse),
		dbWatch:     make(map[string]DbWatchCallback),
		globalLocks: make(map[string]*globalLock),
	}
	runtime.SetFinalizer(a, closeAgentect)
	return a
}

func (a *Agent) start() {
	// perform various start actions
	a.initLog()
	a.initPath()
	a.initDb()
	a.initSeed()
	a.directoryThread()

	// only setSelf() after everything has been started so we know Self() returns a ready instance
	setSelf(a)
}

func closeAgentect(a *Agent) {
	a.Close()
}

func (a *Agent) Close() {
	a.shutdownDb()
	a.shutdownLog()
}

func (a *Agent) doInit(token *jwt.Token) (err error) {
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

	a.cert, err = a.GetInternalCert()
	if err != nil {
		return
	}

	// load CA
	a.ca, _ = a.GetCA()

	// create tls.Config objects
	a.inCfg = new(tls.Config)
	a.outCfg = new(tls.Config)

	// set certificates
	a.inCfg.Certificates = []tls.Certificate{a.cert}
	a.outCfg.Certificates = []tls.Certificate{a.cert}
	a.inCfg.RootCAs = a.ca
	a.outCfg.RootCAs = a.ca

	a.inCfg.NextProtos = []string{"fbin", "p2p"}

	// configure client auth
	a.inCfg.ClientAuth = tls.RequireAndVerifyClientCert
	a.inCfg.ClientCAs = a.ca

	if a.socket == nil {
		a.socket, err = tls.Listen("tcp", ":"+strconv.FormatInt(int64(a.port), 10), a.inCfg)
		if err != nil {
			log.Printf("[agent] failed to listen: %s")
			return
		}
		log.Printf("[agent] Listening on :%d", a.port)
	}

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

func (a *Agent) Id() string {
	return a.id
}

func (a *Agent) Name() (string, string) {
	return a.name, a.hostname
}

func (a *Agent) BroadcastRpc(ctx context.Context, endpoint string, data interface{}) error {
	// send request
	pkt := &PacketRpc{
		SourceId: a.id,
		Endpoint: endpoint,
		Data:     data,
	}

	peers := a.GetPeers()

	if len(peers) == 0 {
		return nil
	}

	for _, p := range peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt2 := &PacketRpc{}
		*pkt2 = *pkt
		pkt2.TargetId = p.id
		go p.Send(ctx, pkt2)
	}

	return nil
}

func (a *Agent) BroadcastPacket(ctx context.Context, pc uint16, data []byte) error {
	peers := a.GetPeers()
	if len(peers) == 0 {
		return nil // nothing to do
	}

	var wg sync.WaitGroup

	for _, p := range peers {
		wg.Add(1)
		go func(p *Peer) {
			defer wg.Done()
			p.WritePacket(ctx, pc, data)
		}(p)
	}

	wg.Wait()
	return nil
}

func (a *Agent) broadcastDbRecord(ctx context.Context, bucket, key, val []byte, v DbStamp) error {
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
		go p.Send(ctx, pkt2)
	}

	return nil
}

type rpcChoiceStruct struct {
	routines uint32
	peer     *Peer
}

func (a *Agent) AnyRpc(ctx context.Context, division string, endpoint string, data interface{}) error {
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
		go i.peer.Send(ctx, pkt)
		return nil
	}

	return errors.New("no peer available")
}

func (a *Agent) DivisionRpc(ctx context.Context, division int, endpoint string, data interface{}) error {
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

	return a.DivisionPrefixRpc(ctx, divMatch, endpoint, data)
}

func (a *Agent) DivisionPrefixRpc(ctx context.Context, divMatch string, endpoint string, data interface{}) error {
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
		go p.Send(ctx, pkt2)
	}

	return nil
}

func (a *Agent) AllRPC(ctx context.Context, endpoint string, data interface{}) ([]interface{}, error) {
	// call method on ALL hosts and collect responses

	// put a timeout on context just in case
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// build response pipe
	res := make(chan *PacketRpcResponse)
	resId := uintptr(unsafe.Pointer(&res))
	a.rpcL.Lock()
	a.rpc[resId] = res
	a.rpcL.Unlock()

	defer func() {
		a.rpcL.Lock()
		delete(a.rpc, resId)
		a.rpcL.Unlock()
	}()

	// prepare request
	pkt := &PacketRpc{
		SourceId: a.id,
		R:        resId,
		Endpoint: endpoint,
		Data:     data,
	}

	// send request
	n, err := a.broadcastRpcPacket(ctx, pkt)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		// no error, no nothing
		return nil, nil
	}

	// collect responses
	var final []interface{}

	for {
		select {
		case v := <-res:
			if v.HasError {
				final = append(final, errors.New(v.Error))
			} else {
				final = append(final, v.Data)
			}
			if len(final) == n {
				return final, nil
			}
		case <-ctx.Done():
			return final, ctx.Err()
		}
	}
}

func (a *Agent) broadcastRpcPacket(ctx context.Context, pkt *PacketRpc) (n int, err error) {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return
	}

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		n += 1
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		pkt2 := &PacketRpc{}
		*pkt2 = *pkt
		pkt2.TargetId = p.id
		go p.Send(ctx, pkt2)
	}

	return
}

func (a *Agent) RPC(ctx context.Context, id string, endpoint string, data interface{}) (interface{}, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("Failed to find peer")
	}

	res := make(chan *PacketRpcResponse)
	resId := uintptr(unsafe.Pointer(&res))
	a.rpcL.Lock()
	a.rpc[resId] = res
	a.rpcL.Unlock()

	defer func() {
		a.rpcL.Lock()
		delete(a.rpc, resId)
		a.rpcL.Unlock()
	}()

	// send request
	pkt := &PacketRpc{
		TargetId: id,
		SourceId: a.id,
		R:        resId,
		Endpoint: endpoint,
		Data:     data,
	}

	p.Send(ctx, pkt)

	// get response
	select {
	case r := <-res:
		if r == nil {
			return nil, errors.New("failed to wait for response")
		}

		err := error(nil)
		if r.HasError {
			err = errors.New(r.Error)
		}

		return r.Data, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (a *Agent) handleRpc(pkt *PacketRpc) error {
	res := PacketRpcResponse{
		SourceId: a.id,
		TargetId: pkt.SourceId,
		R:        pkt.R,
	}

	ctx := context.Background()

	if pkt.R == 0 {
		// no return
		CallRpcEndpoint(pkt.Endpoint, pkt.Data)
		return nil
	}

	func() {
		var err error
		res.Data, err = CallRpcEndpoint(pkt.Endpoint, pkt.Data)
		if err != nil {
			res.Error = err.Error()
			res.HasError = true
		}
	}()

	return a.SendTo(ctx, res.TargetId, res)
}

func (a *Agent) handleRpcResponse(pkt *PacketRpcResponse) error {
	a.rpcL.Lock()
	defer a.rpcL.Unlock()

	c, ok := a.rpc[pkt.R]
	if !ok {
		return nil
	}

	t := time.NewTimer(time.Second)
	defer t.Stop()

	select {
	case c <- pkt:
		// OK
		return nil
	case <-t.C:
		// timeout
		return nil
	}
}

func (a *Agent) dialPeer(host, name string, id string) {
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
	cfg.NextProtos = []string{"fbin"}

	c, err := tls.Dial("tcp", host+":"+strconv.FormatInt(int64(a.port), 10), cfg)
	if err != nil {
		log.Printf("[fleet] failed to connect to peer %s(%s): %s", name, id, err)
		return
	}

	go a.newConn(c)
}

func (a *Agent) IsConnected(id string) bool {
	if id == a.id {
		// we are "connected" to self
		return true
	}
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	_, ok := a.peers[id]
	return ok
}

func (a *Agent) listenLoop() {
	for {
		conn, err := a.socket.Accept()
		if err != nil {
			log.Printf("[fleet] failed to accept connections: %s", err)
			return
		}

		go a.newConn(conn)
	}
}

func (a *Agent) eventLoop() {
	announce := time.NewTicker(30 * time.Second)

	for {
		select {
		case <-announce.C:
			a.doAnnounce()
		}
	}
}

func (a *Agent) doAnnounce() {
	peers := a.GetPeers()

	if len(peers) == 0 {
		return
	}

	x := atomic.AddUint64(&a.announceIdx, 1)

	pkt := &PacketAnnounce{
		Id:   a.id,
		Now:  time.Now(),
		Idx:  x,
		AZ:   a.division,
		NumG: uint32(runtime.NumGoroutine()),
		Meta: a.copyMeta(),
	}

	//log.Printf("[agent] broadcasting announce %+v to %d peers", pkt, len(peers))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	for _, p := range peers {
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		wg.Add(1)
		go func(p *Peer) {
			defer wg.Done()
			err := p.Send(ctx, pkt)
			if err != nil {
				log.Printf("[agent] failed to send announce to %s: %s", p.id, err)
			}
		}(p)
	}
	wg.Wait()
}

func (a *Agent) doBroadcast(ctx context.Context, pkt Packet, except_id string) {
	peers := a.GetPeers()

	if len(peers) == 0 {
		return
	}

	for _, p := range peers {
		if p.id == except_id {
			continue
		}
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		go p.Send(ctx, pkt)
	}
}

func (a *Agent) DumpInfo(w io.Writer) {
	fmt.Fprintf(w, "Fleet Agent Information\n")
	fmt.Fprintf(w, "=======================\n\n")
	fmt.Fprintf(w, "Local name: %s\n", a.name)
	fmt.Fprintf(w, "Division:   %s\n", a.division)
	fmt.Fprintf(w, "Local ID:   %s\n", a.id)
	fmt.Fprintf(w, "Seed ID:    %s (seed stamp: %s)\n", a.SeedId(), a.seed.ts)
	fmt.Fprintf(w, "\n")

	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	t := make(sortablePeers, 0, len(a.peers))

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
		fmt.Fprintf(w, "Offset:   %s\n", p.timeOfft)
		fmt.Fprintf(w, "Routines: %d\n", p.numG)
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "DB keys:\n")
	for _, bk := range []string{"fleet", "global", "app"} {
		var l []string
		if c, err := a.NewDbCursor([]byte(bk)); err == nil {
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

func (a *Agent) GetPeer(id string) *Peer {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()
	return a.peers[id]
}

func (a *Agent) GetPeerByName(name string) *Peer {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	for _, p := range a.peers {
		if p.name == name {
			return p
		}
	}

	return nil
}

func (a *Agent) CountPeers() int {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	return len(a.peers)
}

func (a *Agent) GetPeers() []*Peer {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	res := make([]*Peer, 0, len(a.peers))
	for _, p := range a.peers {
		res = append(res, p)
	}

	sort.Sort(sortablePeers(res))

	return res
}

func (a *Agent) handleAnnounce(ann *PacketAnnounce, fromPeer *Peer) error {
	p := a.GetPeer(ann.Id)

	if p == nil {
		// need to establish link
		//go a.dialPeer(ann.Ip, "", ann.Id)
		log.Printf("[agent] failed to process announce from %s (no such peer)", ann.Id)
		return nil
	}

	return p.processAnnounce(ann, fromPeer)
}

func (a *Agent) SendPacketTo(ctx context.Context, target string, pc uint16, data []byte) error {
	p := a.GetPeer(target)
	if p == nil {
		return ErrPeerNoRoute
	}

	return p.WritePacket(ctx, pc, data)
}

func (a *Agent) SendTo(ctx context.Context, target string, pkt interface{}) error {
	p := a.GetPeer(target) // TODO find best route instead of using GetPeer
	if p == nil {
		return ErrPeerNoRoute
	}

	return p.Send(ctx, pkt)
}

func (a *Agent) MetaSet(key string, value interface{}) {
	a.metaLk.Lock()
	defer a.metaLk.Unlock()

	if a.meta == nil {
		a.meta = make(map[string]interface{})
	}

	a.meta[key] = value
}

func (a *Agent) copyMeta() map[string]interface{} {
	a.metaLk.RLock()
	defer a.metaLk.RUnlock()

	if a.meta == nil {
		return nil
	}

	res := make(map[string]interface{})

	for k, v := range a.meta {
		res[k] = v
	}

	return res
}
