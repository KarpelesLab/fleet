package fleet

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/KarpelesLab/cryptutil"
	"github.com/KarpelesLab/jwt"
)

type directoryPrivate struct {
	// "Private":{"Division":"clfd-nc2oqp-57wv-eoxd-5h3f-3o4eahl4","Id":"clfdh-yiwybb-7rdr-gq5f-fk52-6mmxlxxe"}
	Id       string
	Division string
}

type directoryPeer struct {
	//{"Name":"jp001","Version":"20211010151149/8fed26f","TimeOffset":53348333,"Private":{"Division":"clfd-qepiqm-ufgr-hh3d-v4p5-twwxysdy","Id":"clfdh-d27zrv-bymj-fb3i-fn5x-upy5awea"},"LastSeen":"2021-10-10T09:20:12.006662333Z","IP":"","Token":
	Name     string // "jp001"
	Version  string // "20211010151149/8fed26f"
	Location string
	IP       string   // public ip as seen by directory
	AltIPs   []string // alternative local IPs reported by peer
	Port     int
	Private  *directoryPrivate
}

type directoryNs struct {
	KeyId string
	Name  string
	Peers []*directoryPeer
}

type directoryPingResponse struct {
	Myself    *directoryPeer
	Namespace *directoryNs
}

func (a *Agent) directoryThread() {
	a.spot.WaitOnline(context.Background())

	if a.directoryThreadStart() {
		return
	}

	go func() {
		for {
			// wait
			time.Sleep(15 * time.Minute)
			// and retry
			if a.directoryThreadStart() {
				return
			}
		}
	}()
}

func (a *Agent) directoryThreadStart() bool {
	// this is run in its own gorouting after db is setup
	defer func() {
		// ensure this thread crashing doesn't take the whole process
		if e := recover(); e != nil {
			slog.Error(fmt.Sprintf("[fleet] directory thread panic'd, will retry later. Error: %s\n%s", e, debug.Stack()), "event", "fleet:directory:panic", "category", "go.panic")
		}
	}()

	// attempt to load jwt
	jwtData, err := a.dbFleetGet("internal_key:jwt")
	if err != nil {
		slog.Info(fmt.Sprintf("[fleet] failed to load jwt: %s (will retry soon)", err), "event", "fleet:directory:no_jwt")
		// attempt to get issuer to give us a key
		err = a.performSelfIdentificationAttempt()
		if err == nil {
			// re-attempt to get jwt
			jwtData, err = a.dbFleetGet("internal_key:jwt")
		}
		if err != nil {
			slog.Info(fmt.Sprintf("[fleet] failed to id: %s (will retry later)", err), "event", "fleet:directory:no_selfid")
			return false
		}
	}

	// decode jwt
	jwtInfo, err := jwt.ParseString(string(jwtData))
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] failed to decode jwt: %s", err), "event", "fleet:directory:jwt_invalid")
		return false
	}
	// our tokens have the actual key stored in kid
	key, err := base64.RawURLEncoding.DecodeString(jwtInfo.GetKeyId())
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] failed to decode kid: %s", err), "event", "fleet:directory:jwt_kid_invalid")
		return false
	}
	keyObj, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] failed to parse jwt key: %s", err), "event", "fleet:directory:jwt_pkix_invalid")
		slog.Info("[fleet] removing invalid jwt from database", "event", "fleet:directory:jwt_expunge")
		a.dbFleetDel("internal_key:jwt")
		return false
	}
	// keyObj is a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	err = jwtInfo.Verify(jwt.VerifySignature(keyObj), jwt.VerifyTime(time.Now(), false))
	if err != nil {
		slog.Error(fmt.Sprintf("[fleet] failed to verify jwt: %s", err), "event", "fleet:jwt:verify_fail")
		slog.Info("[fleet] removing invalid jwt from database", "event", "fleet:directory:jwt_expunge")
		a.dbFleetDel("internal_key:jwt")
		return false
	}

	err = a.doInit(jwtInfo)
	if err != nil {
		slog.Warn(fmt.Sprintf("[agent] failed to init agent: %s", err), "event", "fleet:directory:agent_init_fail")
	}

	sgr := jwtInfo.Payload().GetString("sgr") // Spot Group (sha256 hash as hex)
	if sgr == "" {
		slog.Error(fmt.Sprintf("[fleet] JWT missing SpotGroup"), "event", "fleet:directory:jwt_sgr_missing")
		slog.Info("[fleet] removing invalid jwt from database", "event", "fleet:directory:jwt_expunge")
		a.dbFleetDel("internal_key:jwt")
		return false
	}

	// new process, use spot instead of directory to find & talk with other peers
	groupHash, err := hex.DecodeString(sgr)
	if err != nil || len(groupHash) != 32 {
		slog.Error(fmt.Sprintf("[fleet] bad groupHash value: %s", err), "event", "fleet:directory:jwt_sgr_decode_error")
		slog.Info("[fleet] removing invalid jwt from database", "event", "fleet:directory:jwt_expunge")
		a.dbFleetDel("internal_key:jwt")
		return false
	}

	// let's make sure we're in the group
	id := a.spot.IDCard()
	var group []byte
	found := false
	for _, m := range id.Groups {
		mh := sha256.Sum256(m.Key)
		if bytes.Equal(mh[:], groupHash) {
			group = m.Key
			found = true
		}
	}
	if !found {
		selfId := base64.RawURLEncoding.EncodeToString(cryptutil.Hash(id.Self, sha256.New))
		groupId := base64.RawURLEncoding.EncodeToString(groupHash)
		slog.Error(fmt.Sprintf("[fleet] unable to join group as not member of the group myself; self=%s group=%s", selfId, groupId), "event", "fleet:directory:group_join_fail")
		return false
	}
	// new process
	a.setGroup(group)
	a.setStatus(1)
	return true
}

func getLocalIPs() []string {
	var res []string

	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == net.FlagLoopback {
			// ignore loopback interfaces
			continue
		}
		addrs, _ := i.Addrs()
		for _, addr := range addrs {
			res = append(res, addr.String())
		}
	}
	return res
}
