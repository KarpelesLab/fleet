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
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/goupd"
	"golang.org/x/crypto/ssh"
)

type Peer struct {
	c        *tls.Conn
	id       string
	name     string
	division string
	protocol string
	addr     *net.TCPAddr
	valid    bool
	ssh      ssh.Conn
	fbin     ssh.Channel

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

func (a *Agent) newConn(c net.Conn, incoming bool) {
	tc, ok := c.(*tls.Conn)
	if !ok {
		slog.Error(fmt.Sprintf("[fleet] non-tls connection recieved?"), "event", "fleet:peer:non_tls")
		c.Close()
		return
	}

	// make sure handshake has completed
	err := tc.Handshake()
	if err != nil {
		slog.Warn(fmt.Sprintf("[fleet] handshake failed with peer %s: %s", tc.RemoteAddr(), err), "event", "fleet:peer:tls_handshake_fail")
		tc.Close()
		return
	}

	switch tc.ConnectionState().NegotiatedProtocol {
	case "fbin":
		a.handleFleetConn(tc)
		return
	case "fssh":
		a.handleFleetSsh(tc, incoming)
		return
	case "p2p":
		a.handleServiceConn(tc)
		return
	default:
		slog.Warn(fmt.Sprintf("[fleet] invalid protocol %s in connection handshake", tc.ConnectionState().NegotiatedProtocol), "event", "fleet:peer:invalid_proto")
		tc.Close()
	}
}

// TlsProtocols returns a list of TLS protocols managed by the fleet system
// that should be directed to the fleet agent listener
func TlsProtocols() []string {
	return []string{"fssh", "fbin", "p2p"}
}

func (a *Agent) handleFleetConn(tc *tls.Conn) {
	// instanciate peer and fetch certificate
	p := &Peer{
		c:         tc,
		a:         a,
		cnx:       time.Now(),
		protocol:  "fbin",
		addr:      tc.RemoteAddr().(*net.TCPAddr),
		alive:     make(chan struct{}),
		aliveTime: time.Now(),
		annTime:   time.Now(),
		valid:     true,
	}
	err := p.fetchUuidFromCertificate(tc)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] failed to get peer id: %s", err), "event", "fleet:peer:tls_peer_id_missing")
		p.c.Close()
		return
	}
	if p.id == a.id {
		slog.Debug("[fleet] connected to self, closing", "event", "fleet:peer:talking_to_self")
		p.c.Close()
		return
	}

	slog.Debug(fmt.Sprintf("[fleet] Connection with peer %s(%s) established", p.name, p.id), "event", "fleet:peer:connected")

	go p.sendHandshake(context.Background()) // will disappear
	go p.register()

	go p.loop()
	go p.writeLoop()
	go p.monitor()
}

func (a *Agent) handleFleetSsh(tc *tls.Conn, incoming bool) {
	// instanciate peer and fetch certificate
	p := &Peer{
		a:         a,
		cnx:       time.Now(),
		protocol:  "ssh",
		addr:      tc.RemoteAddr().(*net.TCPAddr),
		alive:     make(chan struct{}),
		aliveTime: time.Now(),
		annTime:   time.Now(),
		valid:     true,
	}
	err := p.fetchUuidFromCertificate(tc)
	if err != nil {
		slog.Warn(fmt.Sprintf("[fleet] failed to get peer id: %s", err), "event", "fleet:peer:tls_peerid_missing")
		tc.Close()
		return
	}
	if p.id == a.id {
		slog.Debug(fmt.Sprintf("[fleet] connected to self, closing"), "event", "fleet:peer:talking_to_self")
		tc.Close()
		return
	}

	var chans <-chan ssh.NewChannel
	var reqs <-chan *ssh.Request

	if incoming {
		// we are server
		// NewServerConn(c net.Conn, config *ServerConfig) (*ServerConn, <-chan NewChannel, <-chan *Request, error)
		cfg := &ssh.ServerConfig{
			NoClientAuth:  true, // already authenticated
			ServerVersion: "SSH-2.0-fssh",
		}
		if k, err := a.intCert.PrivateKey(); err == nil {
			if s, err := ssh.NewSignerFromKey(k); err == nil {
				cfg.AddHostKey(s)
			} else {
				slog.Error(fmt.Sprintf("[fleet] SSH server signer failed: %s", err), "event", "fleet:peer:ssh_signer_fail")
			}
		} else {
			slog.Error(fmt.Sprintf("[fleet] failed to fetch host private key: %s", err), "event", "fleet:peer:privkey_fail")
		}
		p.ssh, chans, reqs, err = ssh.NewServerConn(tc, cfg)
	} else {
		// we are client
		cfg := &ssh.ClientConfig{
			User:            "none",
			Auth:            []ssh.AuthMethod{},          // auth method = none
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO compare with ssl key?
			//BannerCallback:
			//ClientVersion:
		}
		p.ssh, chans, reqs, err = ssh.NewClientConn(tc, p.id, cfg)
		fbin, reqs, err := p.ssh.OpenChannel("fbin", nil)
		if err != nil {
			slog.Error(fmt.Sprintf("[fleet] failed to open fbin channel"), "event", "fleet:peer:ssh_fbinch_error")
		} else {
			p.fbin = fbin
			go p.loop()
			go ssh.DiscardRequests(reqs)
		}
	}
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] SSH connection failed: %s", err), "event", "fleet:peer:ssh_fail")
		tc.Close()
		return
	}

	slog.Info(fmt.Sprintf("[fleet] SSH connection with peer %s(%s) established", p.name, p.id), "event", "fleet:peer:ssh_ok")

	go p.handleSshRequests(reqs)
	go p.handleSshChans(chans)

	go p.sendHandshake(context.Background()) // will disappear
	go p.register()

	go p.monitor()
	go p.writeLoop()
}

func (p *Peer) handleSshRequests(reqs <-chan *ssh.Request) {
	defer p.unregister()
	defer p.ssh.Close()

	for req := range reqs {
		switch req.Type {
		case "fbin":
			// payload is 2 bytes packet code followed by binary data
			// this is considered legacy but kept for compatibility
			buf := req.Payload
			if len(buf) < 2 {
				if req.WantReply {
					req.Reply(false, nil)
				}
				break
			}
			pc := binary.BigEndian.Uint16(buf[:2])
			err := p.handleBinary(pc, buf[2:])
			if req.WantReply {
				if err != nil {
					req.Reply(false, []byte(err.Error()))
				} else {
					req.Reply(true, nil)
				}
			}
		default:
			// rpc binreq?
			if endpoint, ok := strings.CutPrefix(req.Type, "rpc/"); ok {
				data, err := CallRpcEndpoint(endpoint, req.Payload)
				if err != nil {
					req.Reply(false, []byte(err.Error()))
				} else {
					req.Reply(true, data.([]byte))
				}
				break
			}
			// unsupported
			req.Reply(false, nil)
		}
	}

	slog.Debug(fmt.Sprintf("[fleet] SSH connection is out of requests"), "event", "fleet:peer:ssh_req_eof")
}

func (p *Peer) handleSshChans(chans <-chan ssh.NewChannel) {
	defer p.unregister()
	defer p.ssh.Close()

	for ch := range chans {
		switch ch.ChannelType() {
		case "p2p":
			addrSplit := strings.Split(string(ch.ExtraData()), ".") // <service>.<id>
			if len(addrSplit) != 2 {
				ch.Reject(ssh.ConnectionFailed, "invalid service request, needs to be <service>.<id>")
				break
			}
			// TODO check if addrSplit[1] is indeed us
			svc := p.a.getService(addrSplit[0])
			if svc == nil {
				// no such service
				ch.Reject(ssh.ConnectionFailed, "no such service")
				break
			}
			nch, reqs, err := ch.Accept()
			if err != nil {
				slog.Error(fmt.Sprintf("[fleet] channel accept failed: %s", err), "event", "fleet:peer:accept_fail")
				break
			}
			go ssh.DiscardRequests(reqs)
			svc <- &quasiConn{Channel: nch, p: p}
		case "fbin":
			if p.fbin != nil {
				p.Close("duplicate fbin chan")
				return
			}
			nch, reqs, err := ch.Accept()
			if err != nil {
				slog.Error(fmt.Sprintf("[fleet] channel accept failed: %s", err), "event", "fleet:peer:accept_fail")
				break
			}
			go ssh.DiscardRequests(reqs)
			p.fbin = nch
			go p.loop()
		default:
			slog.Error(fmt.Sprintf("[fleet] rejecting channel request for %s", ch.ChannelType()), "event", "fleet:peer:channel_reject")
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}

	slog.Debug(fmt.Sprintf("[fleet] SSH connection is out of channels"), "event", "fleet:peer:ssh_chan_eof")
}

func (p *Peer) retryLater(t time.Duration) {
	time.Sleep(t)
	p.a.dialPeer(p.addr.IP.String(), p.addr.Port, p.name, p.id, nil)
}

func (p *Peer) loop() {
	defer p.unregister()

	// read from peer
	header := make([]byte, 6)
	var pc uint16  // packet code
	var ln uint32  // packet len
	var buf []byte // buffer (kept if large enough)

	var c io.Reader
	if p.fbin != nil {
		c = p.fbin
		defer p.ssh.Close()
	} else {
		c = p.c
		defer p.c.Close()
	}

	for {
		_, err := io.ReadFull(c, header)
		if err == nil {
			pc = binary.BigEndian.Uint16(header[:2])
			ln = binary.BigEndian.Uint32(header[2:])

			if ln > PacketMaxLen {
				// too large
				err = fmt.Errorf("rejected packet too large (%d bytes)", ln)
			} else if ln == 0 {
				buf = nil
			} else {
				// always allocate new buffer
				buf = make([]byte, ln)
				_, err = io.ReadFull(c, buf)
			}
		}
		if err == nil {
			err = p.handleBinary(pc, buf)
		}

		if err != nil {
			if err == io.EOF {
				slog.Info(fmt.Sprintf("[fleet] disconnected peer %s(%s) (received EOF)", p.name, p.id), "event", "fleet:peer:eof")
			} else {
				slog.Info(fmt.Sprintf("[fleet] failed to read from peer %s(%s): %s", p.name, p.id, err), "event", "fleet:peer:read_fail")
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

func (p *Peer) writeLoop() {
	if p.ssh != nil {
		defer p.ssh.Close()
	} else {
		defer p.c.Close()
	}
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
				slog.Error(fmt.Sprintf("[fleet] Write to peer failed: %s", err), "event", "fleet:peer:write_fail")
				return
			}
		}
	}
}

func (p *Peer) writev(ctx context.Context, buf ...[]byte) (n int, err error) {
	p.write.Lock()
	defer p.write.Unlock()

	var w io.Writer

	if p.fbin != nil {
		w = p.fbin
	} else {
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
		w = p.c
	}

	for _, b := range buf {
		sn, serr := w.Write(b)
		if sn > 0 {
			n += sn
		}
		if serr != nil {
			err = serr
			if n > 0 {
				slog.Error("partial write on writev(), closing connection", "event", "fleet:peer:error_partial_write", "fleet.peer", p.id)
				p.Close("partial write") // close because that is a partial write
			}
			if p.c != nil {
				p.c.SetWriteDeadline(time.Time{})
			}
			return
		}
	}
	return
}

func (p *Peer) WritePacket(ctx context.Context, pc uint16, data []byte) error {
	if p.fbin == nil && p.ssh != nil {
		// send as fbin request
		pcBin := []byte{byte(pc >> 8), byte(pc)}
		_, _, err := p.ssh.SendRequest("fbin", false, append(pcBin, data...))
		if err != nil {
			slog.Error(fmt.Sprintf("[fleet] WritePacket to %s via SSH failed: %s", p.name, err), "event", "fleet:peer:ssh_write_fail", "fleet.peer", p.id)
		}
		return err
	}

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
	slog.Info(fmt.Sprintf("[fleet] Closing connection to %s(%s): %s", p.name, p.id, reason), "event", "fleet:peer:close", "fleet.peer", p.id)
	if p.ssh != nil {
		return p.ssh.Close()
	}

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
		slog.Info("dropping duplicate connection to peer", "event", "fleet:peer:err_dup", "fleet.peer", p.id)
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
	if p.ssh != nil {
		return p.ssh.RemoteAddr()
	}
	return p.c.RemoteAddr()
}
