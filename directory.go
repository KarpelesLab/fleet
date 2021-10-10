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
	"os"
	"path/filepath"
	"time"

	"github.com/KarpelesLab/goupd"
	"github.com/KarpelesLab/jwt"
)

func directoryThread() {
	// this is run in its own gorouting after db is setup
	defer func() {
		// ensure this thread crashing doesn't take the whole process
		if e := recover(); e != nil {
			log.Printf("[fleet] directory thread panic'd, disabling safely. Error: %s", e)
		}
	}()

	// attempt to load jwt
	jwtData, err := dbSimpleGet([]byte("fleet"), []byte("internal_key:jwt"))
	if err != nil {
		if _, err := os.Stat(filepath.Join(initialPath, "internal_key.jwt")); err == nil {
			// file exists there, read the files
			jwtData, err = ioutil.ReadFile(filepath.Join(initialPath, "internal_key.jwt"))
			if err != nil {
				log.Printf("[fleet] directory jwt failed to load: %s", err)
				return
			}
			// store
			err = dbSimpleSet([]byte("fleet"), []byte("internal_key:jwt"), jwtData)
			if err != nil {
				log.Printf("[fleet] directory jwt failed to store: %s", err)
				return
			}
			// remove file
			os.Remove(filepath.Join(initialPath, "internal_key.jwt"))
		} else {
			log.Printf("[fleet] directory jwt not found, disabling directory registration")
			return
		}
	}

	// decode jwt
	jwtInfo, err := jwt.ParseString(string(jwtData))
	if err != nil {
		log.Printf("[fleet] failed to decode jwt: %s", err)
		return
	}
	// our tokens have the actual key stored in kid
	key, err := base64.RawURLEncoding.DecodeString(jwtInfo.GetKeyId())
	if err != nil {
		log.Printf("[fleet] failed to decode kid: %s", err)
		return
	}
	keyObj, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		log.Printf("[fleet] failed to parse jwt key: %s", err)
		return
	}
	// keyObj is a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey
	err = jwtInfo.Verify(jwt.VerifySignature(keyObj), jwt.VerifyTime(time.Now(), false))
	if err != nil {
		log.Printf("[fleet] failed to verify jwt: %s", err)
		return
	}

	dir := jwtInfo.Payload().GetString("aud") // Audience
	if dir == "" {
		log.Printf("[fleet] directory failed to load: aud claim not found")
		return
	}

	// jwt contains our jwt token, load the certificate too
	cfg, err := GetClientTlsConfig()
	if err != nil {
		log.Printf("[fleet] failed to get client TLS certificate, directory service disabled: %s", err)
		return
	}

	tr := &http.Transport{
		TLSClientConfig: cfg,
		MaxIdleConns:    10,
		IdleConnTimeout: 120 * time.Second,
	}
	client := &http.Client{Transport: tr}

	for {
		// connect to directory, ping, etc
		err = jwtPingDirectory(dir, jwtData, client)
		if err != nil {
			log.Printf("[fleet] ping failed: %s", err)
		}
		time.Sleep(60 * time.Second)
	}
}

func jwtPingDirectory(dir string, jwt []byte, client *http.Client) error {
	u := &url.URL{
		Scheme: "https",
		Host:   dir,
		Path:   "/ping",
	}

	// post body
	post := map[string]interface{}{
		"Name":    Agent.name,
		"Version": goupd.DATE_TAG + "/" + goupd.GIT_TAG,
		"Time":    time.Now().UnixMicro(), // in ms
		"Private": map[string]interface{}{
			"Id":       Agent.id,
			"Division": Agent.division,
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

	if resp.StatusCode > 299 {
		bodyData := make([]byte, 128)
		n, err := resp.Body.Read(bodyData)
		if err != nil {
			return fmt.Errorf("invalid response from server: %s", resp.Status)
		}
		bodyData = bodyData[:n]
		return fmt.Errorf("invalid response from server: %s (data: %s)", resp.Status, bodyData)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	log.Printf("[fleet] debug ping response: %s", buf)

	return nil
}
