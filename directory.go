package fleet

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
	IP       string
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

func directoryThread() {
	if directoryThreadStart() {
		return
	}

	go func() {
		for {
			// wait
			time.Sleep(15 * time.Minute)
			// and retry
			if directoryThreadStart() {
				return
			}
		}
	}()
}

func directoryThreadStart() bool {
	// this is run in its own gorouting after db is setup
	defer func() {
		// ensure this thread crashing doesn't take the whole process
		if e := recover(); e != nil {
			log.Printf("[fleet] directory thread panic'd, disabling safely. Error: %s", e)
		}
	}()

	// attempt to load jwt
	jwtData, err := dbFleetGet("internal_key:jwt")
	if err != nil {
		// attempt to get issuer to give us a key
		log.Printf("[fleet] failed to load jwt: %s (will retry later)", err)
		return false
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
		dbFleetDel("internal_key:jwt")
		return false
	}
	// keyObj is a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	err = jwtInfo.Verify(jwt.VerifySignature(keyObj), jwt.VerifyTime(time.Now(), false))
	if err != nil {
		log.Printf("[fleet] failed to verify jwt: %s", err)
		log.Printf("[fleet] removing invalid jwt from database")
		dbFleetDel("internal_key:jwt")
		return false
	}

	initAgent(jwtInfo)

	dir := jwtInfo.Payload().GetString("aud") // Audience
	if dir == "" {
		log.Printf("[fleet] directory failed to load: aud claim not found")
		return false
	}

	// jwt contains our jwt token, load the certificate too
	cfg, err := GetClientTlsConfig()
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

	go func() {
		for {
			// connect to directory, ping, etc
			err = jwtPingDirectory(dir, jwtData, client)
			if err != nil {
				log.Printf("[fleet] ping failed: %s", err)
			}
			time.Sleep(60 * time.Second)
		}
	}()
	return true
}

func jwtPingDirectory(dir string, jwt []byte, client *http.Client) error {
	u := &url.URL{
		Scheme: "https",
		Host:   dir,
		Path:   "/ping",
	}

	// post body
	post := map[string]interface{}{
		"Name":     Agent.name,
		"Location": Agent.division,
		"Version":  goupd.DATE_TAG + "/" + goupd.GIT_TAG,
		"Time":     time.Now().UnixMicro(), // in ms
		"Private": &directoryPrivate{
			Id:       Agent.id,
			Division: Agent.division,
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
		buf, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("invalid response from server: %s (data: %s)", resp.Status, buf)
	}

	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&res)
	if err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// {"Myself":{"Name":"jp001","Version":"20211010151149/8fed26f","TimeOffset":53348333,"Private":{"Division":"clfd-qepiqm-ufgr-hh3d-v4p5-twwxysdy","Id":"clfdh-d27zrv-bymj-fb3i-fn5x-upy5awea"},"LastSeen":"2021-10-10T09:20:12.006662333Z","IP":"13.230.154.155","Token":"

	//log.Printf("[fleet] debug ping response: %+v", res)

	for _, peer := range res.Namespace.Peers {
		// check if we're connected
		if Agent.IsConnected(peer.Private.Id) {
			continue
		}
		go Agent.dialPeer(peer.IP, peer.Name, peer.Private.Id)
	}

	return nil
}
