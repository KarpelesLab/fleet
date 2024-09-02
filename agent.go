package fleet

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/cloudinfo"
	"github.com/KarpelesLab/emitter"
	"github.com/KarpelesLab/jwt"
	"github.com/KarpelesLab/rchan"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/tpmlib"
	"github.com/quic-go/quic-go"
	bolt "go.etcd.io/bbolt"
)

type GetFileFunc func(*Agent, string) ([]byte, error)

type Agent struct {
	id       string
	name     string
	division string
	hostname string // only the hostname side
	IP       string // ip as seen from outside
	cache    string // location of cache
	spot     *spotlib.Client
	quicT    *quic.Transport
	Events   *emitter.Hub
	group    []byte // Spot group key we are a member of

	inCfg  *tls.Config
	outCfg *tls.Config
	ca     *x509.CertPool

	announceIdx uint64

	peers      map[string]*Peer
	peersMutex sync.RWMutex
	peersCount uint32

	transport http.RoundTripper

	status     int // 0=waiting 1=ready
	statusLock sync.RWMutex
	statusCond *sync.Cond

	// DB
	db          *bolt.DB
	dbWatch     map[string][]DbWatchCallback
	dbWatchLock sync.RWMutex

	// Meta-info
	meta   map[string]any
	metaLk sync.RWMutex

	// getfile callback
	GetFile GetFileFunc

	// seed: use a pointer for atomic seed details update
	seed *seedData

	// locking
	globalLocks   map[string]*globalLock
	globalLocksLk sync.RWMutex

	// cert cache
	pubCert *crtCache
	intCert *crtCache

	// settings
	settings        map[string]any
	settingsUpdated time.Time
	settingsLk      sync.Mutex
}

// New will just initialize a basic agent without any settings
func New(opts ...AgentOption) *Agent {
	a := spawn()
	for _, o := range opts {
		o.apply(a)
	}
	a.start()
	return a
}

// return a new agent using the provided GetFile method
func WithGetFile(f GetFileFunc, opts ...AgentOption) *Agent {
	return New(append([]AgentOption{f}, opts...)...)
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
		dbWatch:     make(map[string][]DbWatchCallback),
		globalLocks: make(map[string]*globalLock),
	}
	a.pubCert = &crtCache{a: a, k: "public_key"}
	a.intCert = &crtCache{a: a, k: "internal_key"}
	a.statusCond = sync.NewCond(a.statusLock.RLocker())
	runtime.SetFinalizer(a, closeAgentect)
	return a
}

func (a *Agent) start() {
	// perform various start actions
	a.initPath()
	a.initDb()
	a.initSeed()
	a.initSpot()
	a.directoryThread()
	a.channelSet()

	// only setSelf() after everything has been started so we know Self() returns a ready instance
	setSelf(a)
}

func closeAgentect(a *Agent) {
	a.Close()
}

func (a *Agent) Close() {
	a.shutdownDb()
	a.shutdownSpot()
}

func (a *Agent) GetStatus() int {
	a.statusLock.RLock()
	defer a.statusLock.RUnlock()
	return a.status
}

func (a *Agent) setStatus(s int) {
	a.statusLock.Lock()
	defer a.statusLock.Unlock()
	a.status = s
	a.statusCond.Broadcast()
}

// WaitReady will lock until the agent is ready for operation (connected to other peers)
func (a *Agent) WaitReady() {
	a.statusLock.RLock()
	defer a.statusLock.RUnlock()

	for {
		if a.status == 1 {
			return
		}
		a.statusCond.Wait()
	}
}

// ExternalKey returns the key associated with the cluster, if any. If this host hasn't
// joined a cluster or the cluster has no shared key, this will return fs.ErrNotExist
func (a *Agent) ExternalKey() (crypto.PrivateKey, error) {
	return a.pubCert.PrivateKey()
}

// InternalKey returns the key associated with the local host, possibly a TPM key if the
// host has a functioning tpm.
func (a *Agent) InternalKey() (crypto.Signer, error) {
	return a.getLocalKey()
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

	// load CA
	a.ca, _ = a.GetCA()

	// create tls.Config objects
	a.inCfg = new(tls.Config)
	a.outCfg = new(tls.Config)

	// set certificates
	a.inCfg.GetCertificate = a.intCert.GetCertificate
	a.outCfg.GetClientCertificate = a.intCert.GetClientCertificate
	a.inCfg.RootCAs = a.ca
	a.outCfg.RootCAs = a.ca

	a.inCfg.NextProtos = []string{"fssh", "fbin", "p2p"}

	// configure client auth
	a.inCfg.ClientAuth = tls.RequireAndVerifyClientCert
	a.inCfg.ClientCAs = a.ca

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

	go a.eventLoop()

	return
}

// Id returns the id of the local node
func (a *Agent) Id() string {
	return a.id
}

// Name returns the name and hostname of the local node
func (a *Agent) Name() (string, string) {
	return a.name, a.hostname
}

// Division returns the division (locality) of the local node
func (a *Agent) Division() string {
	return a.division
}

// AltNames will attempt to return alternative names from the certificate issued to this node
func (a *Agent) AltNames() []string {
	crt, err := a.intCert.GetCertificate(nil)
	if err != nil {
		return nil
	}

	var res []string
	has := make(map[string]bool)

	if crt != nil && crt.Leaf != nil {
		for _, n := range crt.Leaf.DNSNames {
			res = append(res, n)
			has[n] = true
		}
		for _, n := range crt.Leaf.IPAddresses {
			ipstr := n.String()
			res = append(res, ipstr)
			has[ipstr] = true
		}
	}

	// gather cloud info
	info, _ := cloudinfo.Load()
	for _, ip := range info.PublicIP {
		ipstr := ip.String()
		if _, ok := has[ipstr]; !ok {
			res = append(res, ipstr)
			has[ipstr] = true
		}
	}
	for _, ip := range info.PrivateIP {
		ipstr := ip.String()
		if _, ok := has[ipstr]; !ok {
			res = append(res, ipstr)
			has[ipstr] = true
		}
	}

	return res
}

// BroadcastRpc broadcasts the given data to the specified endpoint
func (a *Agent) BroadcastRpc(ctx context.Context, endpoint string, data any) error {
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

func (a *Agent) AnyRpc(ctx context.Context, division string, endpoint string, data any) error {
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

func (a *Agent) DivisionRpc(ctx context.Context, division int, endpoint string, data any) error {
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

func (a *Agent) DivisionPrefixRpc(ctx context.Context, divMatch string, endpoint string, data any) error {
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

func (a *Agent) AllRPC(ctx context.Context, endpoint string, data any) ([]any, error) {
	// call method on ALL hosts and collect responses

	// put a timeout on context just in case
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// build response pipe
	id, res := rchan.New()
	defer id.Release()

	// prepare request
	pkt := &PacketRpc{
		SourceId: a.id,
		R:        id,
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
	var final []any

	for {
		select {
		case vany := <-res:
			v, ok := vany.(*PacketRpcResponse)
			if !ok {
				continue
			}
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

func (a *Agent) AllRpcRequest(ctx context.Context, endpoint string, data []byte) ([]any, error) {
	// call method on ALL hosts and collect responses
	if len(endpoint) > 65535 {
		return nil, ErrEndpointNameLen
	}

	// put a timeout on context just in case
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// build response pipe
	id, res := rchan.New()
	defer id.Release()

	buf := make([]byte, 14)
	binary.BigEndian.PutUint64(buf[:8], uint64(id))
	binary.BigEndian.PutUint32(buf[8:12], 0) // flags
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(endpoint)))
	buf = append(append(buf, endpoint...), data...)

	// send request
	n := 0
	for _, p := range a.GetPeers() {
		if p.id == a.id {
			continue
		}
		n += 1
		go func(p *Peer) {
			err := p.WritePacket(ctx, PacketRpcBinReq, buf)
			if err != nil {
				id.Send(ctx, err)
			}
		}(p)
	}

	// collect responses
	var final []any

	for {
		select {
		case v := <-res:
			final = append(final, v)
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

func (a *Agent) BroadcastRpcBin(ctx context.Context, endpoint string, pkt []byte) (n int, err error) {
	a.peersMutex.RLock()
	defer a.peersMutex.RUnlock()

	if len(a.peers) == 0 {
		return
	}

	if len(endpoint) > 65535 {
		return 0, ErrEndpointNameLen
	}

	buf := make([]byte, 14)
	binary.BigEndian.PutUint64(buf[:8], 0)
	binary.BigEndian.PutUint32(buf[8:12], 0) // flags
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(endpoint)))
	buf = append(append(buf, endpoint...), pkt...)

	var wg sync.WaitGroup

	for _, p := range a.peers {
		if p.id == a.id {
			// do not send to self
			continue
		}
		n += 1
		wg.Add(1)
		// do in gorouting in case connection lags or fails and triggers call to unregister that deadlocks because we hold a lock
		go func(ap *Peer) {
			defer wg.Done()
			ap.WritePacket(ctx, PacketRpcBinReq, buf)
		}(p)
	}

	// wait for all sends to end to make sure pkt can be re-used
	wg.Wait()

	return
}

func (a *Agent) RpcRequest(ctx context.Context, id string, endpoint string, data []byte) ([]byte, error) {
	if len(endpoint) > 65535 {
		return nil, ErrEndpointNameLen
	}

	// send data to given peer
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("failed to find peer")
	}

	resId, res := rchan.New()
	defer resId.Release()

	buf := make([]byte, 14)
	binary.BigEndian.PutUint64(buf[:8], uint64(resId))
	binary.BigEndian.PutUint32(buf[8:12], 0) // flags
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(endpoint)))
	buf = append(append(buf, endpoint...), data...)

	err := p.WritePacket(ctx, PacketRpcBinReq, buf)
	if err != nil {
		return nil, err
	}
	final := <-res

	switch v := final.(type) {
	case error:
		return nil, v
	case []byte:
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported response type %T", final)
	}
}

// RpcSend sends a request but expects no response, failure will only reported if the request failed to be
// sent, and failure on the other side will not be reported
func (a *Agent) RpcSend(ctx context.Context, id string, endpoint string, data []byte) error {
	if len(endpoint) > 65535 {
		return ErrEndpointNameLen
	}

	p := a.GetPeer(id)
	if p == nil {
		return errors.New("failed to find peer")
	}

	buf := make([]byte, 14)
	binary.BigEndian.PutUint64(buf[:8], 0)
	binary.BigEndian.PutUint32(buf[8:12], 0) // flags
	binary.BigEndian.PutUint16(buf[12:14], uint16(len(endpoint)))
	buf = append(append(buf, endpoint...), data...)

	err := p.WritePacket(ctx, PacketRpcBinReq, buf)
	if err != nil {
		slog.Warn(fmt.Sprintf("[fleet] failed sending RPC packet to peer %s: %s", p.name, err), "event", "fleet:rpc:sendfail")
	}
	return err
}

func (a *Agent) RPC(ctx context.Context, id string, endpoint string, data any) (any, error) {
	p := a.GetPeer(id)
	if p == nil {
		return nil, errors.New("failed to find peer")
	}

	resId, res := rchan.New()
	defer resId.Release()

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
	case rany := <-res:
		r, ok := rany.(*PacketRpcResponse)
		if !ok {
			return nil, errors.New("invalid response type")
		}
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

func (a *Agent) handleRpcBin(peer *Peer, buf []byte) error {
	if len(buf) < 14 {
		return errors.New("packet too small")
	}
	// buf format:
	// <reqId>:uint64
	// <flags>:uint32
	// <endpointNameLen>:uint16
	// <endpointName>:string
	// <data>
	id := binary.BigEndian.Uint64(buf[:8])
	flags := binary.BigEndian.Uint32(buf[8:12])
	pfx := buf[:12]
	ln := binary.BigEndian.Uint16(buf[12:14])
	if len(buf) < 14+int(ln) {
		return errors.New("packet too small 2")
	}
	endpoint := string(buf[14 : int(ln)+14])
	buf = buf[int(ln)+14:]

	go func() {
		data, err := CallRpcEndpoint(endpoint, buf)
		if id == 0 {
			// do not send any response
			return
		}

		var res []byte

		if err != nil {
			// report error
			flags |= 0x10000 // ="error"
			res = append(pfx, err.Error()...)
		} else {
			dataB, ok := data.([]byte)
			if !ok {
				err = errors.New("RPC method did not return []byte")
			}
			res = append(pfx, dataB...)
		}

		binary.BigEndian.PutUint32(res[:4], flags) // update flags if needed

		// return result by sending packet
		peer.WritePacket(context.Background(), PacketRpcBinRes, res)
	}()
	return nil
}

func (a *Agent) handleRpcBinResponse(peer *Peer, buf []byte) error {
	if len(buf) < 12 {
		return errors.New("invalid buffer length for response")
	}

	id := rchan.Id(binary.BigEndian.Uint64(buf[:8]))
	c := id.C()
	if c == nil {
		return nil
	}

	flags := binary.BigEndian.Uint32(buf[8:12])
	buf = buf[12:]
	val := any(buf)

	if flags&0x10000 == 0x10000 {
		// error
		val = errors.New(string(buf))
	}

	go func() {
		t := time.NewTimer(time.Second)
		defer t.Stop()

		select {
		case c <- val:
		case <-t.C:
			// timeout
		}
	}()
	return nil
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
	c := pkt.R.C()
	if c == nil {
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

func (a *Agent) eventLoop() {
	announce := time.NewTicker(30 * time.Second)

	for range announce.C {
		a.doAnnounce()
	}
}

func (a *Agent) makeAnnouncePacket() *PacketAnnounce {
	pkt := &PacketAnnounce{
		Id:   a.id,
		Now:  time.Now(),
		Idx:  0,
		AZ:   a.division,
		NumG: uint32(runtime.NumGoroutine()),
		Meta: a.copyMeta(), // TODO we do not need to copy that
	}
	return pkt
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
				slog.Warn(fmt.Sprintf("[agent] failed to send announce to %s: %s", p.id, err), "event", "fleet:agent:announce_fail")
			}
		}(p)
	}
	wg.Wait()
}

func (a *Agent) DumpInfo(w io.Writer) {
	fmt.Fprintf(w, "Fleet Agent Information\n")
	fmt.Fprintf(w, "=======================\n\n")
	fmt.Fprintf(w, "Local name: %s\n", a.name)
	fmt.Fprintf(w, "Division:   %s\n", a.division)
	fmt.Fprintf(w, "Local ID:   %s\n", a.id)
	fmt.Fprintf(w, "Seed ID:    %s (seed stamp: %s)\n", a.SeedId(), a.seed.ts)
	if tk, err := tpmlib.GetKey(); err == nil {
		// we have a tpm key
		fmt.Fprintf(w, "TPM key:    YES (%s)\n", tk)
	}
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
		fmt.Fprintf(w, "Endpoint: %s\n", p.RemoteAddr())
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

// GetPeersCount return the number of existing peers, connected or not. The
// value may be more than the number of entries GetPeers will return as some
// peers may be down or unavailable.
func (a *Agent) GetPeersCount() uint32 {
	return atomic.LoadUint32(&a.peersCount)
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
		slog.Warn(fmt.Sprintf("[agent] failed to process announce from %s (no such peer)", ann.Id), "event", "fleet:agent:igress_announce_no_peer")
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

func (a *Agent) SendTo(ctx context.Context, target string, pkt any) error {
	p := a.GetPeer(target) // TODO find best route instead of using GetPeer
	if p == nil {
		return ErrPeerNoRoute
	}

	return p.Send(ctx, pkt)
}

func (a *Agent) MetaSet(key string, value any) {
	a.metaLk.Lock()
	defer a.metaLk.Unlock()

	if a.meta == nil {
		a.meta = make(map[string]any)
	}

	a.meta[key] = value
}

func (a *Agent) copyMeta() map[string]any {
	a.metaLk.RLock()
	defer a.metaLk.RUnlock()

	if a.meta == nil {
		return nil
	}

	res := make(map[string]any)

	for k, v := range a.meta {
		res[k] = v
	}

	return res
}

// Settings fetches the current settings from the global system and returns these
// if the system is initializing, this will block until initialization is done
func (a *Agent) Settings() (map[string]any, error) {
	a.settingsLk.Lock()
	defer a.settingsLk.Unlock()

	if a.settings == nil {
		a.settingsUpdated = time.Now()
		err := a.updateSettings()
		if err != nil {
			return nil, err
		}
		// update done
		return a.settings, nil
	}
	if time.Since(a.settingsUpdated) > 24*time.Hour {
		a.settingsUpdated = time.Now()
		go a.updateSettings()
	}
	return a.settings, nil
}

func (a *Agent) updateSettings() error {
	// attempt to load settings
	v, err := a.dbFleetLoad("settings:json")
	if err != nil {
		return err
	}
	var res map[string]any
	err = json.Unmarshal(v, &res)
	if err != nil {
		return err
	}

	a.settings = res
	return nil
}

func (a *Agent) GetStringSetting(v string) string {
	s, _ := a.Settings()
	if res, ok := s[v].(string); ok {
		return res
	}
	return os.Getenv(v)
}
