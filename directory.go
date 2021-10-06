package fleet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
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
	jwt, err := dbSimpleGet([]byte("fleet"), []byte("internal_key:jwt"))
	if err != nil {
		if _, err := os.Stat(filepath.Join(initialPath, "internal_key.jwt")); err == nil {
			// file exists there, read the files
			jwt, err = ioutil.ReadFile(filepath.Join(initialPath, "internal_key.jwt"))
			if err != nil {
				log.Printf("[fleet] directory jwt failed to load: %s", err)
				return
			}
			// store
			err = dbSimpleSet([]byte("fleet"), []byte("internal_key:jwt"), jwt)
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

	// check jwt signature against kid found in header
	jwtData, err := loadSysJwt(jwt)
	if err != nil {
		log.Printf("[fleet] invalid jwt for directory: %s", err)
		return
	}

	dir, ok := jwtData["directory"].(string)
	if !ok {
		log.Printf("[fleet] directory failed to load: %s", err)
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
		err = jwtPingDirectory(dir, jwt, client)
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
		return fmt.Errorf("invalid response from server: %s", resp.Status)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	log.Printf("[fleet] debug ping response: %s", buf)

	return nil
}

func loadSysJwt(jwt []byte) (map[string]interface{}, error) {
	jwtA := bytes.SplitN(jwt, []byte{'.'}, 3)
	if len(jwtA) != 3 {
		return nil, fmt.Errorf("invalid jwt, expecting 3 parts, got %d", len(jwtA))
	}
	// decode
	head, err := base64.RawURLEncoding.DecodeString(string(jwtA[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, header decode failed: %w", err)
	}
	body, err := base64.RawURLEncoding.DecodeString(string(jwtA[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, body decode failed: %w", err)
	}
	sign, err := base64.RawURLEncoding.DecodeString(string(jwtA[2]))
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, signature decode failed: %w", err)
	}

	signString := jwt[:len(head)+len(body)+1] // head+'.'+body

	// parse header
	var hInfo map[string]string // header will only include string values
	err = json.Unmarshal(head, &hInfo)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, header parse failed: %w", err)
	}

	// check signature. We need "alg" and "kid"
	kid, ok := hInfo["kid"]
	if !ok {
		return nil, fmt.Errorf("invalid jwt, missing kid")
	}
	alg, ok := hInfo["alg"]
	if !ok {
		return nil, fmt.Errorf("invalid jwt, missing alg")
	}

	key, err := base64.RawURLEncoding.DecodeString(kid)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, failed to decode kid: %w", err)
	}
	keyObj, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("invalid jwt, failed to parse kid: %w", err)
	}
	// keyObj is a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey

	// check signature
	switch alg {
	case "RS256": // RSA
		pk, ok := keyObj.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid jwt key, expected RSA, got %T", keyObj)
		}
		h := sha256.Sum256(signString)
		err := rsa.VerifyPKCS1v15(pk, crypto.SHA256, h[:], sign)
		if err != nil {
			return nil, fmt.Errorf("invalid jwt key, bad RSA signature: %w", err)
		}
	case "ES256": // ECDSA
		pk, ok := keyObj.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid jwt key, expected ECDSA, got %T", keyObj)
		}
		h := sha256.Sum256(signString)
		if !ecdsa.VerifyASN1(pk, h[:], sign) {
			return nil, fmt.Errorf("invalid jwt key, bad ECDSA signature")
		}
	case "EdDSA": // EDDSA
		pk, ok := keyObj.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid jwt key, expected Ed25519, got %T", keyObj)
		}
		if !ed25519.Verify(pk, signString, sign) {
			return nil, fmt.Errorf("invalid jwt key, bad Ed25519 signature")
		}
	default:
		return nil, fmt.Errorf("unsupported signature alg=%s", alg)
	}

	// signature is good, parse body
	var res map[string]interface{}
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
