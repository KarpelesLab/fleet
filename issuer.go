package fleet

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"
)

func SetIssuer(url string) {
	// this means that GetFile(internal_key.jwt) and such should call our issuer
	//

	// Issuer API is a url receiving a POST body containing "ts", "key" and "file"
	// - ts is a timestamp in microtime. Not two requests should have the same ts
	// - key is a base64url-encoded public key
	// - file is the file requested
	// additionally, the headers include a "Sec-Body-Signature" value which is the
	// signature of the json body encoded in base64url. The issuer must verify the
	// signature, should verify additional information (source ip, etc) and decide
	// to issue or not the requested file.

	GetFile = func(f string) ([]byte, error) {
		if f == "internal_key.key" {
			// this will result in a loop call when using getLocalKey(), so reject it now
			return nil, fs.ErrNotExist
		}

		// get local key
		key, err := getLocalKey()
		if err != nil {
			return nil, err
		}

		pubBin, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return nil, err
		}

		// fetch our local hostname to be included in request (just informative)
		hn, _ := os.Hostname()

		body := map[string]interface{}{
			"ts":   time.Now().UnixMicro(),
			"file": f,
			"key":  base64.RawURLEncoding.EncodeToString(pubBin),
			"host": hn,
		}

		// prepare request body (will never fail)
		bodyBin, _ := json.Marshal(body)

		// sign request
		// Sign(rand io.Reader, digest []byte, opts SignerOpts) (signature []byte, err error)
		var sig []byte

		switch key.(type) {
		case ed25519.PrivateKey:
			// need to not hash
			sig, err = key.Sign(rand.Reader, bodyBin, crypto.Hash(0))
		default:
			h := sha256.Sum256(bodyBin)
			sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
		}
		if err != nil {
			return nil, fmt.Errorf("while signing request: %w", err)
		}

		log.Printf("POST to issuer %s: %s", url, bodyBin)

		// Pass "sig" in header
		req, err := http.NewRequest("POST", url, bytes.NewReader(bodyBin))
		req.Header.Add("Sec-Body-Signature", base64.RawURLEncoding.EncodeToString(sig))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("while calling issuer: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("failed to read %s: %s", f, resp.Status)
		}

		// read body in a buffer
		buf := &bytes.Buffer{}

		_, err = io.Copy(buf, resp.Body)
		if err != nil {
			return nil, err
		}

		return buf.Bytes(), nil
	}
}
