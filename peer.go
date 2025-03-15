// Package fleet provides a distributed peer-to-peer communication framework.
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

// Peer represents a remote node in the fleet network.
// Each peer has a unique identity, can exchange messages, and maintains
// status information about the connection.
type Peer struct {
	// Connection and identity
	c        *tls.Conn         // TLS connection to the peer
	id       string            // Unique ID, format is "k:..."
	idcard   *cryptutil.IDCard // Identity card with cryptographic information
	name     string            // Human-readable name
	division string            // Logical grouping/location (like a datacenter/region)
	valid    bool              // Whether this peer is valid/authenticated

	// Status tracking
	annIdx    uint64        // Last announcement index received
	numG      uint32        // Number of goroutines on peer (for load balancing)
	cnx       time.Time     // When the connection was established
	annTime   time.Time     // Last announcement time
	aliveTime time.Time     // Last time peer was confirmed alive
	timeOfft  time.Duration // Time offset between local and peer clocks
	Ping      time.Duration // Measured ping time (RTT) to peer

	// Parent agent
	a *Agent // Parent agent that owns this peer

	// Synchronization
	mutex sync.RWMutex // General mutex for peer state
	unreg sync.Once    // Ensures unregister only happens once
	write sync.Mutex   // Mutex for writing to connection

	// Lifecycle management
	alive chan struct{} // Channel closed when peer is no longer alive

	// Metadata
	meta   map[string]any // Custom metadata for this peer
	metaLk sync.Mutex     // Lock for metadata access
}

// makePeer creates a new peer connection from a cryptographic identity card.
// This function establishes the initial connection to a peer, verifies it's alive,
// and initializes the peer object.
//
// Parameters:
//   - pid: The cryptographic identity card of the remote peer
//
// Returns a connected Peer object or nil if the connection fails or is to self.
func (a *Agent) makePeer(pid *cryptutil.IDCard) *Peer {
	// Generate unique ID from the peer's public key
	idStr := "k." + base64.RawURLEncoding.EncodeToString(cryptutil.Hash(pid.Self, sha256.New))

	// Avoid connecting to self
	if idStr == a.id {
		return nil
	}

	// Check if we're already connected to this peer
	if p := a.GetPeer(idStr); p != nil {
		return p
	}

	// Create a new peer instance with basic information
	p := &Peer{
		a:         a,                   // Parent agent
		id:        idStr,               // Unique ID
		idcard:    pid,                 // Identity card
		cnx:       time.Now(),          // Connection time
		alive:     make(chan struct{}), // Channel for lifecycle management
		aliveTime: time.Now(),          // Marked as alive now
		annTime:   time.Now(),          // Last announcement time is now
		valid:     true,                // Peer is valid initially
	}

	// Test the connection by fetching peer information
	info, err := p.fetchInfo(30 * time.Second)
	if err != nil {
		// Peer is not responding, consider it dead
		slog.Debug(fmt.Sprintf("[fleet] failed to test-fetch announce from peer %s: %s", p.id, err),
			"event", "fleet:peer:ann_fetch_fail")
		return nil
	}

	// Update peer information from the response
	p.name = info.Name
	p.division = info.Division

	// Signal version information for update management
	goupd.SignalVersionChannel(info.Git, info.Build, info.Channel)

	slog.Debug(fmt.Sprintf("[fleet] Connection with peer %s(%s) established", p.name, p.id),
		"event", "fleet:peer:connected")

	// Start background processes for this peer
	go p.sendHandshake(context.Background()) // Send our handshake to the peer
	go p.monitor()                           // Start monitoring connection health

	return p
}

// Addr returns the network address of the peer.
// This implements the net.Addr interface for compatibility with networking code.
func (p *Peer) Addr() net.Addr {
	return spotlib.SpotAddr(p.id)
}

// IsAlive checks if the peer is still considered alive based on recent announcements.
// A peer is considered alive if we've received an announcement within the last 5 minutes.
// This is used to filter out dead peers when getting the list of active peers.
func (p *Peer) IsAlive() bool {
	// We perform fetchAnnounce once per minute in the monitor() loop,
	// so if we haven't received an announcement in 5 minutes, the peer is likely down.
	return time.Since(p.annTime) < 5*time.Minute
}

// fetchAnnounce retrieves the latest announcement from the peer.
// This function queries the peer for its current state and metadata.
//
// Parameters:
//   - timeout: Maximum time to wait for a response
//
// Returns:
//   - A PacketAnnounce with the peer's current state
//   - An error if the operation fails
func (p *Peer) fetchAnnounce(timeout time.Duration) (*PacketAnnounce, error) {
	// Create a context with the specified timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Query the peer using the spot library
	res, err := p.a.spot.Query(ctx, p.id+"/fleet-announce", nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal the CBOR-encoded response
	var ann *PacketAnnounce
	err = cbor.Unmarshal(res, &ann)
	if err != nil {
		return nil, err
	}

	return ann, nil
}

// fetchInfo retrieves identity information from the peer.
// This is used during connection establishment to get the peer's name, division, etc.
//
// Parameters:
//   - timeout: Maximum time to wait for a response
//
// Returns:
//   - A PacketHandshake with the peer's identity information
//   - An error if the operation fails
func (p *Peer) fetchInfo(timeout time.Duration) (*PacketHandshake, error) {
	// Create a context with the specified timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Query the peer using the spot library
	res, err := p.a.spot.Query(ctx, p.id+"/fleet-info", nil)
	if err != nil {
		return nil, err
	}

	// Unmarshal the CBOR-encoded response
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
		// write seed back
		go p.WritePacket(context.Background(), PacketSeed, p.a.seedData())
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

// Send sends a high-level packet to the peer.
// This method serializes the packet using gob encoding and sends it through the legacy packet protocol.
//
// Parameters:
//   - ctx: Context for the operation (for cancellation and timeout)
//   - pkt: The packet to send (must be registered with gob.Register)
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (p *Peer) Send(ctx context.Context, pkt Packet) error {
	// Serialize the packet using gob encoding
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	enc.Encode(&pkt) // & is important to encode the actual packet, not a pointer to it

	// Send as a legacy packet (which uses gob serialization)
	return p.WritePacket(ctx, PacketLegacy, buf.Bytes())
}

// WritePacket sends a binary packet with a specified packet code to the peer.
// This is a lower-level method that sends raw binary data with a packet type identifier.
//
// Parameters:
//   - ctx: Context for the operation (for cancellation and timeout)
//   - pc: Packet code identifying the type of packet (see const.go for codes)
//   - data: Raw binary data to send
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (p *Peer) WritePacket(ctx context.Context, pc uint16, data []byte) error {
	// Create binary packet code header (2 bytes, big-endian)
	pcBin := []byte{byte(pc >> 8), byte(pc)}

	// Send to the peer through the spot protocol, including the packet code prefix
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
