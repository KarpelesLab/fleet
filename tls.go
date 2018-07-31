package fleet

import (
	"crypto/tls"
	"errors"
	"os"
)

// GetTlsConfig returns TLS config suitable for making public facing ssl
// servers.
func GetTlsConfig() (*tls.Config, error) {
	if _, err := os.Stat("public_key.pem"); err == nil {
		cert, err := tls.LoadX509KeyPair("public_key.pem", "public_key.key")
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	if _, err := os.Stat("internal_key.pem"); err == nil {
		cert, err := tls.LoadX509KeyPair("internal_key.pem", "internal_key.key")
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	return nil, errors.New("failed to load TLS certificates")
}

func GetClientTlsConfig() (*tls.Config, error) {
	if _, err := os.Stat("internal_key.pem"); err == nil {
		cert, err := tls.LoadX509KeyPair("internal_key.pem", "internal_key.key")
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	return nil, errors.New("failed to load TLS certificates")
}
