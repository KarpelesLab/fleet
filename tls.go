package fleet

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
)

func (a *Agent) getLocalKey() (crypto.Signer, error) {
	keyPem, err := a.dbFleetGet("internal_key:key")
	if err != nil {
		// we might be able to use a tpm key (we only do that if there was no key)
		if res, err := a.getTpmKey(); err == nil {
			return res, nil
		}
		// gen & save a new key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate local key: %w", err)
		}
		// encode to DER
		key_der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal pkcs8 key: %w", err)
		}
		// encode to PEM
		key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key_der})
		// store in DB
		a.dbSimpleSet([]byte("fleet"), []byte("internal_key:key"), key_pem)

		return key, nil
	}

	// decode PEM key
	pdata, _ := pem.Decode(keyPem)
	if pdata == nil || pdata.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key in internal_key:key")
	}

	// parse pkcs8
	keyIntf, err := x509.ParsePKCS8PrivateKey(pdata.Bytes)
	if err != nil {
		return nil, fmt.Errorf("while decoding pkcs8 key: %w", err)
	}
	if key, ok := keyIntf.(crypto.Signer); ok {
		return key, nil
	}
	// should not happen
	return nil, fmt.Errorf("failed to convert key type %T into crypto.Signer", keyIntf)
}

// KeyShake128 uses PKCS8 private key blob as hash key
func (a *Agent) KeyShake128(N []byte) (sha3.ShakeHash, error) {
	keyPem, err := a.dbFleetGet("internal_key:key")
	if err != nil {
		// call getLocalKey() to generate key
		_, err := a.getLocalKey()
		if err != nil {
			return nil, err
		}
		keyPem, err = a.dbFleetGet("internal_key:key")
		if err != nil {
			return nil, err
		}
	}

	// decode PEM key
	pdata, _ := pem.Decode(keyPem)
	if pdata == nil || pdata.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key in internal_key:key")
	}

	v := sha3.NewCShake128(N, pdata.Bytes)

	return v, nil
}

// KeySha256 uses PKCS8 private key blob as hash key
func (a *Agent) KeyShake256(N []byte) (sha3.ShakeHash, error) {
	keyPem, err := a.dbFleetGet("internal_key:key")
	if err != nil {
		// call getLocalKey() to generate key
		_, err := a.getLocalKey()
		if err != nil {
			return nil, err
		}
		keyPem, err = a.dbFleetGet("internal_key:key")
		if err != nil {
			return nil, err
		}
	}

	// decode PEM key
	pdata, _ := pem.Decode(keyPem)
	if pdata == nil || pdata.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid private key in internal_key:key")
	}

	v := sha3.NewCShake256(N, pdata.Bytes)

	return v, nil
}

func (a *Agent) GenInternalCert() (tls.Certificate, error) {
	log.Printf("[tls] Generating new CA & client certificates")
	// generate a new CA & certificate
	ca_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// get key
	key, err := a.getLocalKey()
	if err != nil {
		return tls.Certificate{}, err
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return tls.Certificate{}, err
	}

	host, err := os.Hostname()
	if err != nil {
		// error getting hostname?
		host = "localhost"
	}

	// generate CA cert
	// copy value
	tplCA := tplCAcrt
	tplCA.NotBefore = time.Now()
	tplCA.NotAfter = tplCA.NotBefore.Add(10 * 365 * 24 * time.Hour) // +10 years (more or less)

	ca_crt_der, err := x509.CreateCertificate(rand.Reader, &tplCA, &tplCA, ca_key.Public(), ca_key)
	if err != nil {
		return tls.Certificate{}, err
	}

	ca_crt, err := x509.ParseCertificate(ca_crt_der)
	if err != nil {
		return tls.Certificate{}, err
	}

	// generate client cert & sign
	tplUsr := tplUsrCrt
	tplUsr.SerialNumber = big.NewInt(0).SetBytes(id[:])
	tplUsr.Subject.CommonName = host
	tplUsr.NotBefore = time.Now()
	tplUsr.NotAfter = tplUsr.NotBefore.Add(1 * 365 * 24 * time.Hour) // +10 years (more or less)

	crt_der, err := x509.CreateCertificate(rand.Reader, &tplUsr, ca_crt, key.Public(), ca_key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// encode keys
	ca_key_der, err := x509.MarshalPKCS8PrivateKey(ca_key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// store stuff as PEM
	ca_crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca_crt_der})
	crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt_der})
	ca_key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ca_key_der})

	// store
	a.dbSimpleSet([]byte("fleet"), []byte("internal_key:crt"), crt_pem)
	a.dbSimpleSet([]byte("global"), []byte("internal:ca:master"), ca_crt_pem)
	a.dbSimpleSet([]byte("fleet"), []byte("ca_key:key"), ca_key_pem)

	log.Printf("[tls] New certificate: %s%s%s", ca_crt_pem, ca_key_pem, crt_pem)

	return tls.Certificate{Certificate: [][]byte{crt_der}, PrivateKey: key}, nil
}

// return internal certificate (cached)
func (a *Agent) GetInternalCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return a.intCert.GetCertificate(h)
}

func (a *Agent) GetCA() (*x509.CertPool, error) {
	ca := x509.NewCertPool()

	// get records
	c, err := a.NewDbCursor([]byte("global"))
	count := 0

	if err == nil {
		defer c.Close()
		k, v := c.Seek([]byte("internal:ca:"))
		for {
			if k == nil {
				break
			}
			ca.AppendCertsFromPEM(v)
			count++
			k, v = c.Next()
		}
	}

	if count == 0 {
		// nothing found in db, check for file?
		err := a.getFile("internal_ca.pem", func(ca_data []byte) error {
			ca.AppendCertsFromPEM(ca_data)
			// store in db
			err = a.dbSimpleSet([]byte("global"), []byte("internal:ca:legacy_import"), ca_data)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return ca, nil
}

// GetTlsConfig returns TLS config suitable for making public facing ssl
// servers.
func (a *Agent) GetTlsConfig() (*tls.Config, error) {
	cfg := new(tls.Config)
	cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if crt, err := a.pubCert.GetCertificate(h); err == nil {
			return crt, nil
		}
		if h.ServerName != "" {
			return GetSelfsignedCertificate(h.ServerName)
		}
		return a.intCert.GetCertificate(h)
	}
	a.SeedTlsConfig(cfg)
	a.ConfigureTlsServer(cfg)
	return cfg, nil
}

func (a *Agent) GetPublicCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return a.pubCert.GetCertificate(h)
}

func (a *Agent) GetInternalTlsConfig() (*tls.Config, error) {
	cfg := new(tls.Config)
	cfg.GetCertificate = a.intCert.GetCertificate
	a.SeedTlsConfig(cfg)
	a.ConfigureTlsServer(cfg)
	return cfg, nil
}

func (a *Agent) GetClientTlsConfig() (*tls.Config, error) {
	cfg := new(tls.Config)
	cfg.GetClientCertificate = a.intCert.GetClientCertificate
	return cfg, nil
}

func (a *Agent) ConfigureTlsServer(cfg *tls.Config) {
	// perform some basic settings to ensure server is secure
	cfg.MinVersion = tls.VersionTLS12
	cfg.CurvePreferences = []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256}
	cfg.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
}
