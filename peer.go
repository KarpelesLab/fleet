package fleet

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/goupd"
)

type Peer struct {
	c         *tls.Conn
	outStream [][]byte
	id        string
	name      string
	division  string
	addr      *net.TCPAddr
	valid     bool

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
}

func (a *Agent) newConn(c net.Conn) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		log.Printf("[fleet] non-tls connection recieved?")
		c.Close()
		return
	}

	// make sure handshake has completed
	err := tc.Handshake()
	if err != nil {
		log.Printf("[fleet] handshake failed with peer %s: %s", tc.RemoteAddr(), err)
		tc.Close()
		return
	}

	switch tc.ConnectionState().NegotiatedProtocol {
	case "fbin":
		a.handleFleetConn(tc)
		return
	case "p2p":
		a.handleServiceConn(tc)
		return
	default:
		tc.Close()
		log.Printf("[fleet] invalid protocol in connection handshake")
	}
}

func (a *Agent) handleFleetConn(tc *tls.Conn) {
	// instanciate peer and fetch certificate
	p := &Peer{
		c:         tc,
		a:         a,
		cnx:       time.Now(),
		addr:      tc.RemoteAddr().(*net.TCPAddr),
		alive:     make(chan struct{}),
		aliveTime: time.Now(),
		annTime:   time.Now(),
		valid:     true,
	}
	err := p.fetchUuidFromCertificate()
	if err != nil {
		log.Printf("[fleet] failed to get peer id: %s", err)
		p.c.Close()
		return
	}
	if p.id == a.id {
		log.Printf("[fleet] connected to self, closing")
		p.c.Close()
		return
	}

	log.Printf("[fleet] Connection with peer %s established", p.id)

	go p.sendHandshake(context.Background()) // will disappear
	go p.register()

	go p.loop()
	go p.writeLoop()
	go p.monitor()
}

func (p *Peer) retryLater(t time.Duration) {
	time.Sleep(t)
	p.a.dialPeer(p.addr.IP.String(), p.name, p.id)
}

func (p *Peer) loop() {
	defer p.unregister()
	defer p.c.Close()

	// read from peer
	header := make([]byte, 6)
	var pc uint16  // packet code
	var ln uint32  // packet len
	var buf []byte // buffer (kept if large enough)

	for {
		_, err := io.ReadFull(p.c, header)
		if err == nil {
			pc = binary.BigEndian.Uint16(header[:2])
			ln = binary.BigEndian.Uint32(header[2:])

			if ln > PacketMaxLen {
				// too large
				err = fmt.Errorf("rejected packet too large (%d bytes)", ln)
			} else if ln == 0 {
				if buf != nil {
					// set buf length to 0 but do not drop buf
					buf = buf[:0]
				}
			} else if int(ln) <= cap(buf) {
				// can store this in the current buffer
				buf = buf[:ln]
				_, err = io.ReadFull(p.c, buf)
			} else {
				// allocate new buffer
				buf = make([]byte, ln)
				_, err = io.ReadFull(p.c, buf)
			}
		}
		if err == nil {
			err = p.handleBinary(pc, buf)
		}

		if err != nil {
			if err == io.EOF {
				log.Printf("[fleet] disconnected peer %s (received EOF)", p.id)
			} else {
				log.Printf("[fleet] failed to read from peer %s: %s", p.id, err)
			}

			if p.valid {
				go p.retryLater(10 * time.Second)
			}

			return
		}
	}
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
	case PacketClose:
		log.Printf("[fleet] Closing peer connection because: %s", data)
		return io.EOF
	default:
		if pc >= PacketCustom && pc <= PacketCustomMax {
			// custom packet
			return callCustomHandler(p, pc, data)
		}
	}
	return nil
}

func (p *Peer) handleLegacy(data []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(data))
	var pkt Packet

	err := dec.Decode(&pkt)
	if err != nil {
		return err
	}
	return p.handlePacket(pkt)
}

func (p *Peer) monitor() {
	defer p.unregister()
	t := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-p.alive:
			p.Close("alive channel closed")
			return
		case <-t.C:
			if time.Since(p.aliveTime) > time.Minute {
				p.Close("alive time timeout")
				return
			}
		}
	}
}

func (p *Peer) handlePacket(pktI interface{}) error {
	switch pkt := pktI.(type) {
	case *PacketHandshake:
		if pkt.Id != p.id {
			return errors.New("invalid handshake")
		}
		p.name = pkt.Name
		p.division = pkt.Division
		goupd.SignalVersion(pkt.Git, pkt.Build)
		// TODO calculate offset
		return nil
	case *PacketSeed:
		return p.a.handleNewSeed(pkt.Seed, pkt.Time)
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
		return nil
	}

	p.annIdx = ann.Idx
	p.annTime = ann.Now
	atomic.StoreUint32(&p.numG, ann.NumG)

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

func (p *Peer) fetchUuidFromCertificate() error {
	// grab certificate
	chains := p.c.ConnectionState().VerifiedChains
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

func (p *Peer) writeLoop() {
	defer p.c.Close()
	t := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-p.alive:
			// closed channel
			return
		case now := <-t.C:
			// send new alive packet
			v := DbStamp(now).Bytes()
			err := p.WritePacket(context.Background(), PacketPing, v)
			if err != nil {
				log.Printf("[fleet] Write to peer failed: %s", err)
				return
			}
		}
	}
}

func (p *Peer) writev(ctx context.Context, buf ...[]byte) (n int, err error) {
	p.write.Lock()
	defer p.write.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) < 0 {
			// write error but non closing
			return 0, os.ErrDeadlineExceeded
		}
		p.c.SetWriteDeadline(deadline)
	} else {
		// reset deadline
		p.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	}

	for _, b := range buf {
		sn, serr := p.c.Write(b)
		if sn > 0 {
			n += sn
		}
		if serr != nil {
			err = serr
			p.c.Close()
			return
		}
	}
	return
}

func (p *Peer) WritePacket(ctx context.Context, pc uint16, data []byte) error {
	pcBin := []byte{byte(pc >> 8), byte(pc)}
	ln := len(data)
	lnBin := []byte{
		byte(ln >> 24),
		byte(ln >> 16),
		byte(ln >> 8),
		byte(ln),
	}
	_, err := p.writev(ctx, pcBin, lnBin, data)
	return err
}

func (p *Peer) Close(reason string) error {
	log.Printf("[fleet] Closing connection to %s: %s", p.id, reason)
	p.c.SetWriteDeadline(time.Now().Add(1 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := p.WritePacket(ctx, PacketClose, []byte(reason))
	if err != nil {
		return err
	}
	return p.c.Close()
}

func (p *Peer) register() {
	a := p.a
	a.peersMutex.Lock()
	defer a.peersMutex.Unlock()

	old, ok := a.peers[p.id]
	if ok && old != p {
		go p.Close("already connected, dropping new connection")
		return
	}

	a.peers[p.id] = p
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
	}
	err := p.Send(ctx, pkt)
	if err != nil {
		return err
	}
	p.WritePacket(ctx, PacketPing, DbStamp(time.Now()).Bytes())
	p.Send(ctx, p.a.databasePacket())
	return p.Send(ctx, p.a.seedPacket())
}
