package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/goupd"
	"github.com/KarpelesLab/spotlib"
	"github.com/fxamacker/cbor/v2"
)

type Peer struct {
	c        *tls.Conn
	id       string // key id, format is k:...
	idcard   *cryptutil.IDCard
	name     string // name found in membership of group sgr
	division string // division
	valid    bool

	annIdx    uint64
	numG      uint32
	cnx       time.Time
	annTime   time.Time
	aliveTime time.Time
	timeOfft  time.Duration
	Ping      time.Duration

	a *Agent

	mutex sync.RWMutex
	unreg sync.Once
	write sync.Mutex

	alive chan struct{}

	meta   map[string]any
	metaLk sync.Mutex
}

func (a *Agent) makePeer(pid *cryptutil.IDCard) *Peer {
	idStr := "k." + base64.RawURLEncoding.EncodeToString(cryptutil.Hash(pid.Self, sha256.New))

	if idStr == a.id {
		// avoid connect to self
		return nil
	}

	// check if already connected
	if p := a.GetPeer(idStr); p != nil {
		return p
	}

	// instanciate peer and fetch certificate
	p := &Peer{
		a:         a,
		id:        idStr,
		idcard:    pid,
		cnx:       time.Now(),
		alive:     make(chan struct{}),
		aliveTime: time.Now(),
		annTime:   time.Now(),
		valid:     true,
	}

	// attempt to fetch announce
	info, err := p.fetchInfo(30 * time.Second)
	if err != nil {
		// no response → dead?
		slog.Debug(fmt.Sprintf("[fleet] failed to test-fetch announce from peer %s: %s", p.id, err), "event", "fleet:peer:ann_fetch_fail")
		return nil
	}

	p.name = info.Name
	p.division = info.Division
	goupd.SignalVersionChannel(info.Git, info.Build, info.Channel)

	slog.Debug(fmt.Sprintf("[fleet] Connection with peer %s(%s) established", p.name, p.id), "event", "fleet:peer:connected")

	go p.sendHandshake(context.Background()) // will disappear
	go p.monitor()
	return p
}

func (p *Peer) Addr() net.Addr {
	return spotlib.SpotAddr(p.id)
}

func (p *Peer) IsAlive() bool {
	// we perform fetchAnnounce once per minute
	return time.Since(p.annTime) < 5*time.Minute
}

func (p *Peer) fetchAnnounce(timeout time.Duration) (*PacketAnnounce, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := p.a.spot.Query(ctx, p.id+"/fleet-announce", nil)
	if err != nil {
		return nil, err
	}
	var ann *PacketAnnounce
	err = cbor.Unmarshal(res, &ann)
	if err != nil {
		return nil, err
	}
	return ann, nil
}

func (p *Peer) fetchInfo(timeout time.Duration) (*PacketHandshake, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res, err := p.a.spot.Query(ctx, p.id+"/fleet-info", nil)
	if err != nil {
		return nil, err
	}
	var info *PacketHandshake
	err = cbor.Unmarshal(res, &info)
	if err != nil {
		return nil, err
	}
	return info, nil
}

func (p *Peer) handleIncomingFbin(buf []byte) error {
	if len(buf) < 2 {
		return nil
	}
	pc := binary.BigEndian.Uint16(buf[:2])
	buf = buf[2:]

	return p.handleBinary(pc, buf)
}

func (p *Peer) handleBinary(pc uint16, data []byte) error {
	switch pc {
	case PacketLegacy:
		return p.handleLegacy(data)
	case PacketPing:
		p.aliveTime = time.Now()
		var t DbStamp
		err := t.UnmarshalBinary(data)
		if err != nil {
			return err
		}
		p.timeOfft = p.aliveTime.Sub(time.Time(t))
		return p.WritePacket(context.Background(), PacketPong, data)
	case PacketPong:
		var t DbStamp
		err := t.UnmarshalBinary(data)
		if err != nil {
			return err
		}
		p.Ping = time.Since(time.Time(t))
		return nil
	case PacketLockReq:
		return p.a.handleLockReq(p, data)
	case PacketLockRes:
		return p.a.handleLockRes(p, data)
	case PacketLockConfirm:
		return p.a.handleLockConfirm(p, data)
	case PacketLockRelease:
		return p.a.handleLockRelease(p, data)
	case PacketClose:
		slog.Info(fmt.Sprintf("[fleet] Closing peer connection because: %s", data), "event", "fleet:peer:close_req")
		return io.EOF
	case PacketSeed:
		if len(data) < 16 {
			return fmt.Errorf("PacketSeed too short")
		}
		var t DbStamp
		err := t.UnmarshalBinary(data[:16])
		if err != nil {
			return err
		}
		return p.a.handleNewSeed(data[16:], time.Time(t))
	case PacketRpcBinReq:
		return p.a.handleRpcBin(p, data)
	case PacketRpcBinRes:
		return p.a.handleRpcBinResponse(p, data)
	default:
		if pc >= PacketCustom && pc <= PacketCustomMax {
			// custom packet
			return callCustomHandler(p, pc, data)
		} else {
			slog.Warn(fmt.Sprintf("[fleet] unknown packet received 0x%04x", pc), "event", "fleet:peer:unknown_packet")
		}
	}
	return nil
}

func (p *Peer) handleLegacy(data []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var pkt Packet

	err := dec.Decode(&pkt)
	if err != nil {
		slog.Info(fmt.Sprintf("notice: failed to decode gob: %s", err), "event", "fleet:peer:gob_parse_fail")
		return nil
	}
	return p.handlePacket(pkt)
}

func (p *Peer) monitor() {
	if !p.register() {
		p.Close("duplicate")
		// already there
		return
	}
	defer p.unregister()
	t := time.NewTicker(60 * time.Second)

	for {
		select {
		case <-p.alive:
			p.Close("alive channel closed")
			return
		case <-t.C:
			ann, err := p.fetchAnnounce(15 * time.Second)
			if err == nil {
				p.a.handleAnnounce(ann, p)
			}
		}
	}
}

func (p *Peer) handlePacket(pktI Packet) error {
	switch pkt := pktI.(type) {
	case *PacketHandshake:
		if pkt.Id != p.id {
			return errors.New("invalid handshake")
		}
		p.name = pkt.Name
		p.division = pkt.Division
		goupd.SignalVersionChannel(pkt.Git, pkt.Build, pkt.Channel)
		// TODO calculate offset
		return nil
	case *PacketAnnounce:
		return p.a.handleAnnounce(pkt, p)
	case *PacketRpc:
		if pkt.TargetId != p.a.id {
			// fw
			return p.a.SendTo(context.Background(), pkt.TargetId, pkt)
		}
		// we don't really care about the source, just do the rpc thing
		return p.a.handleRpc(pkt)
	case *PacketRpcResponse:
		return p.a.handleRpcResponse(pkt)
	case *PacketDbRecord:
		if pkt.TargetId != p.a.id {
			// fw
			return p.a.SendTo(context.Background(), pkt.TargetId, pkt)
		}
		// let the db handle that
		return p.a.feedDbSet(pkt.Bucket, pkt.Key, pkt.Val, pkt.Stamp)
	case *PacketDbRequest:
		if pkt.TargetId != p.a.id {
			// fw
			return p.a.SendTo(context.Background(), pkt.TargetId, pkt)
		}
		// grab from db
		return p.handleDbRequest(pkt)
	case *PacketDbVersions:
		for _, v := range pkt.Info {
			if p.a.needDbEntry(v.Bucket, v.Key, v.Stamp) {
				if err := p.Send(context.Background(), &PacketDbRequest{TargetId: p.id, SourceId: p.a.id, Bucket: v.Bucket, Key: v.Key}); err != nil {
					return err
				}
			}
		}
		return nil
	default:
		return errors.New("unsupported packet")
	}
}

func (p *Peer) processAnnounce(ann *PacketAnnounce, fromPeer *Peer) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if ann.Idx <= p.annIdx {
		// already seen this announce, ignore it
		//log.Printf("[agent] got announce %d but already seen %d", ann.Idx, p.annIdx)
		return nil
	}

	p.annIdx = ann.Idx
	p.annTime = ann.Now
	atomic.StoreUint32(&p.numG, ann.NumG)
	p.setMeta(ann.Meta)

	// send response
	//p.a.TrySendTo(ann.Id, &PacketPong{TargetId: ann.Id, SourceId: p.a.id, Now: ann.Now})

	// broadcast
	//p.a.doBroadcast(ann, fromPeer.id)

	return nil
}

func (p *Peer) handleDbRequest(pkt *PacketDbRequest) error {
	val, stamp, err := p.a.dbGetVersion([]byte(pkt.Bucket), []byte(pkt.Key))
	if err != nil {
		// ignore it
		return nil
	}

	// send response
	res := &PacketDbRecord{
		TargetId: pkt.SourceId,
		SourceId: p.a.id,
		Stamp:    stamp,
		Bucket:   pkt.Bucket,
		Key:      pkt.Key,
		Val:      val,
	}

	return p.Send(context.Background(), res)
}

func (p *Peer) fetchUuidFromCertificate(tc *tls.Conn) error {
	// grab certificate
	chains := tc.ConnectionState().VerifiedChains
	if len(chains) == 0 {
		return errors.New("no peer certificate?")
	}
	if len(chains[0]) == 0 {
		return errors.New("no peer certificate? (2)")
	}

	peer_cert := chains[0][0] // *x509.Certificate
	// grab id
	peer_subject := peer_cert.Subject
	peer_id := ""
	for _, name := range peer_subject.Names {
		// oid(2.5.4.45) = UniqueIdentifier
		if !name.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 45}) {
			continue
		}

		peer_id = name.Value.(string)
		break
	}

	if peer_id == "" {
		return errors.New("failed to get peer id from cert")
	}

	p.id = peer_id
	return nil
}

// Id returns the peer's internal ID, which is unique and can be used to send
// packets to this peer specifically in the future.
func (p *Peer) Id() string {
	return p.id
}

// Name returns this peer's name
func (p *Peer) Name() string {
	return p.name
}

// Division returns this peer's division string
func (p *Peer) Division() string {
	return p.division
}

// Agent returns the Agent object associated with this peer
func (p *Peer) Agent() *Agent {
	return p.a
}

func (p *Peer) Send(ctx context.Context, pkt Packet) error {
	//log.Printf("[debug] sending packet %T to %s with context", pkt, p.id)
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	enc.Encode(&pkt) // & is important
	return p.WritePacket(ctx, PacketLegacy, buf.Bytes())
}

func (p *Peer) WritePacket(ctx context.Context, pc uint16, data []byte) error {
	// send as fbin request
	pcBin := []byte{byte(pc >> 8), byte(pc)}
	return p.a.spot.SendTo(ctx, p.id+"/fleet-fbin", append(pcBin, data...))
}

func (p *Peer) Close(reason string) error {
	slog.Info(fmt.Sprintf("[fleet] Closing connection to %s(%s): %s", p.name, p.id, reason), "event", "fleet:peer:close", "fleet.peer", p.id)
	// unregister will close p.alive that will end all goroutines for this peer
	go p.unregister()
	return nil
}

func (p *Peer) register() bool {
	a := p.a
	a.peersMutex.Lock()
	defer a.peersMutex.Unlock()

	old, ok := a.peers[p.id]
	if ok && old != p {
		slog.Info("dropping duplicate connection to peer", "event", "fleet:peer:err_dup", "fleet.peer", p.id)
		return false
	}

	a.peers[p.id] = p
	return true
}

func (p *Peer) unregister() {
	p.unreg.Do(func() {
		close(p.alive) // no more alive

		a := p.a

		a.peersMutex.Lock()
		defer a.peersMutex.Unlock()

		old, ok := a.peers[p.id]
		if ok && old == p {
			delete(a.peers, p.id)
		}
	})
}

func (p *Peer) sendHandshake(ctx context.Context) error {
	pkt := &PacketHandshake{
		Id:       p.a.id,
		Name:     p.a.name,
		Division: p.a.division,
		Now:      time.Now(),
		Git:      goupd.GIT_TAG,
		Build:    goupd.DATE_TAG,
		Channel:  goupd.CHANNEL,
	}
	err := p.Send(ctx, pkt)
	if err != nil {
		return err
	}
	p.WritePacket(ctx, PacketPing, DbStamp(time.Now()).Bytes())
	p.Send(ctx, p.a.databasePacket())
	return p.WritePacket(ctx, PacketSeed, p.a.seedData())
}

func (p *Peer) Meta() map[string]any {
	p.metaLk.Lock()
	defer p.metaLk.Unlock()

	return p.meta
}

func (p *Peer) setMeta(v map[string]any) {
	p.metaLk.Lock()
	defer p.metaLk.Unlock()

	p.meta = v
}

func (p *Peer) String() string {
	if p.name != "" {
		return p.name
	}
	return p.id
}

func (p *Peer) RemoteAddr() net.Addr {
	return p.Addr()
}
