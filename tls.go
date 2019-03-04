package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

func GenInternalCert() (tls.Certificate, error) {
	log.Printf("[tls] Generating new CA & client certificates")
	// generate a new CA & certificate
	ca_key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	// generate key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	crt_der, err := x509.CreateCertificate(rand.Reader, &tplUsr, ca_crt, key.Public(), ca_key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// encode keys
	ca_key_der, err := x509.MarshalPKCS8PrivateKey(ca_key)
	if err != nil {
		return tls.Certificate{}, err
	}

	key_der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	// store stuff as PEM
	ca_crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca_crt_der})
	crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt_der})
	ca_key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ca_key_der})
	key_pem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key_der})

	log.Printf("[tls] New certificate: %s%s%s%s", ca_crt_pem, ca_key_pem, crt_pem, key_pem)

	return tls.Certificate{Certificate: [][]byte{crt_der}, PrivateKey: key}, nil
}

func GetInternalCert() (tls.Certificate, error) {
	// get internal certificate
	crt, err := dbSimpleGet([]byte("fleet"), []byte("internal_key:crt"))
	if err != nil {
		// failed to load?
		if _, err := os.Stat(filepath.Join(initialPath, "internal_key.pem")); err == nil {
			// file exists there, read the files
			crt, err = ioutil.ReadFile(filepath.Join(initialPath, "internal_key.pem"))
			if err != nil {
				return tls.Certificate{}, err
			}
			key, err := ioutil.ReadFile(filepath.Join(initialPath, "internal_key.key"))
			if err != nil {
				return tls.Certificate{}, err
			}
			// store into db
			err = dbSimpleSet([]byte("fleet"), []byte("internal_key:crt"), crt)
			if err != nil {
				return tls.Certificate{}, err
			}
			err = dbSimpleSet([]byte("fleet"), []byte("internal_key:key"), crt)
			if err != nil {
				return tls.Certificate{}, err
			}
			// remove files
			os.Remove(filepath.Join(initialPath, "internal_key.pem"))
			os.Remove(filepath.Join(initialPath, "internal_key.key"))
			// return
			return tls.X509KeyPair(crt, key)
		}
		return GenInternalCert()
	}

	key, err := dbSimpleGet([]byte("fleet"), []byte("internal_key:key"))
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(crt, key)
}

func GetDefaultPublicCert() (tls.Certificate, error) {
	// get internal certificate
	crt, err := dbSimpleGet([]byte("fleet"), []byte("public_key:crt"))
	if err != nil {
		// failed to load?
		if _, err := os.Stat(filepath.Join(initialPath, "public_key.pem")); err == nil {
			// file exists there, read the files
			crt, err = ioutil.ReadFile(filepath.Join(initialPath, "public_key.pem"))
			if err != nil {
				return tls.Certificate{}, err
			}
			key, err := ioutil.ReadFile(filepath.Join(initialPath, "public_key.key"))
			if err != nil {
				return tls.Certificate{}, err
			}
			// store into db
			err = dbSimpleSet([]byte("fleet"), []byte("public_key:crt"), crt)
			if err != nil {
				return tls.Certificate{}, err
			}
			err = dbSimpleSet([]byte("fleet"), []byte("public_key:key"), crt)
			if err != nil {
				return tls.Certificate{}, err
			}
			// remove files
			os.Remove(filepath.Join(initialPath, "public_key.pem"))
			os.Remove(filepath.Join(initialPath, "public_key.key"))
			// return
			return tls.X509KeyPair(crt, key)
		}
	}

	key, err := dbSimpleGet([]byte("fleet"), []byte("public_key:key"))
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(crt, key)
}

func GetCA() (*x509.CertPool, error) {
	ca := x509.NewCertPool()

	// get records
	c, err := NewDbCursor([]byte("global"))
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
		if ca_data, err := ioutil.ReadFile(filepath.Join(initialPath, "internal_ca.pem")); err == nil {
			ca.AppendCertsFromPEM(ca_data)
			// store in db
			err = dbSimpleSet([]byte("global"), []byte("internal:ca:legacy_import"), ca_data)
			if err == nil {
				os.Remove(filepath.Join(initialPath, "internal_ca.pem"))
			}
		}
	}

	return ca, nil
}

// GetTlsConfig returns TLS config suitable for making public facing ssl
// servers.
func GetTlsConfig() (*tls.Config, error) {
	if cert, err := GetDefaultPublicCert(); err == nil {
		cfg := new(tls.Config)
		cfg.Certificates = []tls.Certificate{cert}
		SeedTlsConfig(cfg)
		ConfigureTlsServer(cfg)
		return cfg, nil
	}

	if cert, err := GetInternalCert(); err == nil {
		cfg := new(tls.Config)
		cfg.Certificates = []tls.Certificate{cert}
		SeedTlsConfig(cfg)
		ConfigureTlsServer(cfg)
		return cfg, nil
	}

	return nil, errors.New("failed to load TLS certificates")
}

func GetClientTlsConfig() (*tls.Config, error) {
	if cert, err := GetInternalCert(); err == nil {
		cfg := new(tls.Config)
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}

	return nil, errors.New("failed to load TLS certificates")
}

func ConfigureTlsServer(cfg *tls.Config) {
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
