package fleet

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
)

// GetTlsConfig returns TLS config suitable for making public facing ssl
// servers.
func GetTlsConfig() (*tls.Config, error) {
	if _, err := os.Stat(filepath.Join(initialPath, "public_key.pem")); err == nil {
		cert, err := tls.LoadX509KeyPair(filepath.Join(initialPath, "public_key.pem"), filepath.Join(initialPath, "public_key.key"))
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	if _, err := os.Stat(filepath.Join(initialPath, "internal_key.pem")); err == nil {
		cert, err := tls.LoadX509KeyPair(filepath.Join(initialPath, "internal_key.pem"), filepath.Join(initialPath, "internal_key.key"))
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	return nil, errors.New("failed to load TLS certificates")
}

func GetClientTlsConfig() (*tls.Config, error) {
	if _, err := os.Stat(filepath.Join(initialPath, "internal_key.pem")); err == nil {
		cert, err := tls.LoadX509KeyPair(filepath.Join(initialPath, "internal_key.pem"), filepath.Join(initialPath, "internal_key.key"))
		if err == nil {
			cfg := new(tls.Config)
			cfg.Certificates = []tls.Certificate{cert}
			return cfg, nil
		}
	}

	return nil, errors.New("failed to load TLS certificates")
}
