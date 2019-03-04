package fleet

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

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
