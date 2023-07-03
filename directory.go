package fleet

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/goupd"
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
			log.Printf("[fleet] directory thread panic'd, will retry later. Error: %s\n%s", e, debug.Stack())
		}
	}()

	// attempt to load jwt
	jwtData, err := a.dbFleetGet("internal_key:jwt")
	if err != nil {
		log.Printf("[fleet] failed to load jwt: %s (will retry soon)", err)
		// attempt to get issuer to give us a key
		err = a.performSelfIdentificationAttempt()
		if err == nil {
			// re-attempt to get jwt
			jwtData, err = a.dbFleetGet("internal_key:jwt")
		}
		if err != nil {
			log.Printf("[fleet] failed to id: %s (will retry later)", err)
			return false
		}
	}

	// decode jwt
	jwtInfo, err := jwt.ParseString(string(jwtData))
	if err != nil {
		log.Printf("[fleet] failed to decode jwt: %s", err)
		return false
	}
	// our tokens have the actual key stored in kid
	key, err := base64.RawURLEncoding.DecodeString(jwtInfo.GetKeyId())
	if err != nil {
		log.Printf("[fleet] failed to decode kid: %s", err)
		return false
	}
	keyObj, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		log.Printf("[fleet] failed to parse jwt key: %s", err)
		log.Printf("[fleet] removing invalid jwt from database")
		a.dbFleetDel("internal_key:jwt")
		return false
	}
	// keyObj is a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	err = jwtInfo.Verify(jwt.VerifySignature(keyObj), jwt.VerifyTime(time.Now(), false))
	if err != nil {
		log.Printf("[fleet] failed to verify jwt: %s", err)
		log.Printf("[fleet] removing invalid jwt from database")
		a.dbFleetDel("internal_key:jwt")
		return false
	}

	err = a.doInit(jwtInfo)
	if err != nil {
		log.Printf("[agent] failed to init agent: %s", err)
	}

	dir := jwtInfo.Payload().GetString("aud") // Audience
	if dir == "" {
		log.Printf("[fleet] directory failed to load: aud claim not found")
		return false
	}

	// jwt contains our jwt token, load the certificate too
	cfg, err := a.GetClientTlsConfig()
	if err != nil {
		log.Printf("[fleet] failed to get client TLS certificate, directory service disabled: %s", err)
		return false
	}

	tr := &http.Transport{
		TLSClientConfig: cfg,
		MaxIdleConns:    10,
		IdleConnTimeout: 120 * time.Second,
	}
	client := &http.Client{Transport: tr}

	a.setStatus(1)

	go func() {
		for {
			// connect to directory, ping, etc
			err = a.jwtPingDirectory(dir, jwtData, client)
			if err != nil {
				log.Printf("[fleet] ping failed: %s", err)
			}
			time.Sleep(60 * time.Second)
		}
	}()
	return true
}

func (a *Agent) jwtPingDirectory(dir string, jwt []byte, client *http.Client) error {
	u := &url.URL{
		Scheme: "https",
		Host:   dir,
		Path:   "/ping",
	}

	// post body
	post := map[string]any{
		"Name":     a.name,
		"Location": a.division,
		"Version":  goupd.CHANNEL + "/" + goupd.DATE_TAG + "/" + goupd.GIT_TAG,
		"Time":     time.Now().UnixMicro(), // in ms
		"AltIPs":   getLocalIPs(),
		"Port":     a.port,
		"Private": &directoryPrivate{
			Id:       a.id,
			Division: a.division,
		},
	}
	postJson, err := json.Marshal(post)
	if err != nil {
		return err
	}

	//log.Printf("[ping] %s", u)
	req, err := http.NewRequest("POST", u.String(), bytes.NewReader(postJson))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(jwt))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var res *directoryPingResponse

	if resp.StatusCode > 299 {
		buf, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("invalid response from server: %s (data: %s)", resp.Status, buf)
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&res)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// {"Myself":{"Name":"jp001","Version":"20211010151149/8fed26f","TimeOffset":53348333,"Private":{"Division":"clfd-qepiqm-ufgr-hh3d-v4p5-twwxysdy","Id":"clfdh-d27zrv-bymj-fb3i-fn5x-upy5awea"},"LastSeen":"2021-10-10T09:20:12.006662333Z","IP":"13.230.154.155","Token":"

	//log.Printf("[fleet] debug ping response: %+v", res)
	a.IP = res.Myself.IP

	atomic.StoreUint32(&a.peersCount, uint32(len(res.Namespace.Peers)))

	for _, peer := range res.Namespace.Peers {
		// check if we're connected
		if a.IsConnected(peer.Private.Id) {
			continue
		}
		go a.dialPeer(peer.IP, peer.Port, peer.Name, peer.Private.Id, peer.AltIPs)
	}

	return nil
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
