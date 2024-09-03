package fleet

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"log/slog"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"
	"github.com/fxamacker/cbor/v2"
	"github.com/quic-go/quic-go"
)

func (a *Agent) initSpot() {
	k, err := a.getLocalKey()
	if err != nil {
		slog.Debug(fmt.Sprintf("failed to fetch local key: %s", err), "event", "fleet:spot:key_fail")
		return
	}
	kc := cryptutil.NewKeychain()
	if tk, ok := k.(interface{ Keychain() *cryptutil.Keychain }); ok {
		kc = tk.Keychain()
	} else {
		kc.AddKey(k)
	}
	meta := map[string]string{"agent": "go-fleet"}
	if info, ok := debug.ReadBuildInfo(); ok {
		meta["project"] = path.Base(info.Path)
	}
	a.spot, err = spotlib.New(kc, meta)
	if err != nil {
		slog.Debug(fmt.Sprintf("failed to init spot: %s", err), "event", "fleet:spot:init_fail")
	}
	// we use spot's events handler so some events like "status" (0|1) are easily available
	a.Events = a.spot.Events
	a.id = a.spot.TargetId()

	pkt, err := a.spot.ListenPacket("fleet-packet")
	if err != nil {
		log.Printf("no? err=%s", err)
	} else {
		a.quicT = &quic.Transport{
			Conn:               pkt,
			ConnectionIDLength: 4,
		}
	}

	a.spot.SetHandler("ping", a.spotPingHandler)
	a.spot.SetHandler("fleet-announce", a.spotAnnounceHandler)
	a.spot.SetHandler("fleet-fbin", a.spotFbinHandler)
}

func (a *Agent) shutdownSpot() {
	if a.spot != nil {
		a.spot.Close()
		a.spot = nil
	}
}

func (a *Agent) spotPingHandler(msg *spotproto.Message) ([]byte, error) {
	return msg.Body, nil
}

func (a *Agent) spotAnnounceHandler(msg *spotproto.Message) ([]byte, error) {
	// return announce packet
	pkt := a.makeAnnouncePacket()
	return cbor.Marshal(pkt)
}

func (a *Agent) spotFbinHandler(msg *spotproto.Message) ([]byte, error) {
	// got a fbin message from another peer, find it first
	s := msg.Sender // k:xxx/yyy
	if pos := strings.IndexByte(s, '/'); pos > 0 {
		s = s[:pos]
	}
	p := a.GetPeer(s)
	if p == nil {
		// check if the id is part of the group
		if a.group != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			id, err := a.spot.GetIDCardForRecipient(ctx, s)
			if err == nil {
				if a.isFriend(id) {
					// instanciate peer
					p = a.makePeer(id)
				}
			}
		}
		// p might not be nil anymore at this point, check
		if p == nil {
			slog.Debug(fmt.Sprintf("[fleet] failed to locate peer %s", s), "event", "fleet:spot:peer_not_found")
			return nil, nil
		}
	}
	err := p.handleIncomingFbin(msg.Body)
	if err != nil {
		slog.Debug(fmt.Sprintf("[fleet] incoming packet handling failed: %s", err), "event", "fleet:spot:fbin_err")
	}
	return nil, nil
}

// isFriend returns true if id is member of our group
func (a *Agent) isFriend(id *cryptutil.IDCard) bool {
	grp := a.group
	if grp == nil {
		return false
	}

	for _, m := range id.Groups {
		if bytes.Equal(m.Key, grp) {
			return true
		}
	}
	return false
}
