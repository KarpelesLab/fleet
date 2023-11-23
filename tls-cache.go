package fleet

import (
	"crypto"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type crtCache struct {
	a   *Agent
	k   string
	lk  sync.Mutex
	t   time.Time
	crt *tls.Certificate
	err error
}

func (c *crtCache) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	crt, err := c.GetCertificate(nil)
	if err != nil || crt == nil {
		// error happened, but we don't care, let's just try without certificate.
		// Go documentation: GetClientCertificate must return non-nil
		return &tls.Certificate{}, nil
	}
	return crt, nil
}

func (c *crtCache) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if time.Since(c.t) < time.Hour*24 {
		return c.crt, c.err
	}
	c.lk.Lock()
	defer c.lk.Unlock()

	if time.Since(c.t) < time.Hour*24 {
		return c.crt, c.err
	}
	c.t = time.Now()

	c.crt, c.err = c.loadCert(true)
	if c.err != nil {
		slog.Warn(fmt.Sprintf("[tls] Failed to fetch %s certificate: %s", c.k, c.err), "event", "fleet:tls:fetch_fail")
	}

	return c.crt, c.err
}

func (c *crtCache) PrivateKey() (crypto.PrivateKey, error) {
	if time.Since(c.t) < time.Hour*24 {
		if c.err != nil {
			return nil, c.err
		}
		return c.crt.PrivateKey, nil
	}

	c.lk.Lock()
	defer c.lk.Unlock()

	if time.Since(c.t) < time.Hour*24 {
		if c.err != nil {
			return nil, c.err
		}
		return c.crt.PrivateKey, nil
	}

	c.t = time.Now()

	c.crt, c.err = c.loadCert(true)
	if c.err != nil {
		slog.Warn(fmt.Sprintf("[tls] Failed to fetch %s certificate: %s", c.k, c.err), "event", "fleet:tls:fetch_fail")
	}

	if c.err != nil {
		return nil, c.err
	}
	return c.crt.PrivateKey, nil
}

// loadCert actually fetches the certificate and instanciates a tls.Certificate
func (c *crtCache) loadCert(allowRetry bool) (*tls.Certificate, error) {
	crt, err := c.a.dbFleetLoad(c.k + ":crt")
	if err != nil {
		return nil, err
	}
	key, err := c.a.dbFleetGet(c.k + ":key")
	if err != nil && c.k == "internal_key" {
		// check for tpm key
		var s crypto.Signer
		s, err = c.a.getTpmKey()
		if err == nil {
			// we need to generate the appropriate object to use this certificate with the tpm
			res := &tls.Certificate{}
			var derBlock *pem.Block
			for {
				derBlock, crt = pem.Decode(crt)
				if derBlock == nil {
					break
				}
				if derBlock.Type == "CERTIFICATE" {
					res.Certificate = append(res.Certificate, derBlock.Bytes)
				}
			}
			if len(res.Certificate) == 0 {
				return nil, errors.New("tls: failed to find any PEM data in internal_key:crt certificate input")
			}
			// note that we aren't checking if the certificate matches the key, maybe we should but it's not cheap on an external auth device
			res.PrivateKey = s
			return res, nil
		}
	}
	if err != nil {
		return nil, err
	}

	res, err := tls.X509KeyPair(crt, key)
	if err != nil {
		// remove from local data cache and try again to see if that helps
		if allowRetry {
			c.a.dbFleetDel(c.k+":crt", c.k+":key")
			return c.loadCert(false)
		}
		// give up
		return nil, fmt.Errorf("while instanciating tls keypair: %w", err)
	}
	return &res, nil
}
