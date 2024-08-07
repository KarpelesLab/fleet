package fleet

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/KarpelesLab/tpmlib"
)

type crtCache struct {
	a   *Agent
	k   string
	lk  sync.Mutex
	t   time.Time
	crt *tls.Certificate
	exp time.Time // expiration time
	err error
}

func (c *crtCache) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	crt, _ := c.GetCertificate(nil)
	if crt == nil {
		// error happened, but we don't care, let's just try without certificate.
		// Go documentation: unlike GetCertificate, GetClientCertificate must return non-nil
		return &tls.Certificate{}, nil
	}
	return crt, nil
}

func (c *crtCache) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if time.Until(c.exp) > 0 && time.Since(c.t) < time.Hour*24 {
		return c.crt, c.err
	}

	c.lk.Lock()
	defer c.lk.Unlock()

	if time.Until(c.exp) > 0 && time.Since(c.t) < time.Hour*24 {
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
		s, err := tpmlib.GetKey()
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

	res, err := crtCacheLoadAndCheck(crt, key)
	if err != nil {
		// remove from local data cache and try again to see if that helps
		if allowRetry {
			c.a.dbFleetDel(c.k+":crt", c.k+":key")
			return c.loadCert(false)
		}
		// give up
		c.exp = time.Now().Add(time.Hour) // force retry in 1h
		return nil, fmt.Errorf("while instanciating tls keypair: %w", err)
	} else {
		// set expiration 24 hours before actual expiration, typically we fetch the new cert sooner
		c.exp = res.Leaf.NotAfter.Add(-24 * time.Hour)
	}
	return &res, nil
}

func crtCacheLoadAndCheck(certPEMBlock, keyPEMBlock []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		return cert, err
	}
	// ensure leaf is loaded (tls.X509KeyPair will not set it, but maybe it will in the future?)
	if cert.Leaf == nil {
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return cert, err
		}
		cert.Leaf = x509Cert
	}
	// check leaf for expiration (returning an error allows clearing cache & fetching of new certificate)
	now := time.Now()
	if now.Before(cert.Leaf.NotBefore) {
		return cert, fmt.Errorf("certificate is not valid yet (now=%s notbefore=%s)", now, cert.Leaf.NotBefore)
	}
	if now.After(cert.Leaf.NotAfter.Add(-24 * time.Hour)) {
		return cert, fmt.Errorf("certificate has expired (now=%s notafter=%s)", now, cert.Leaf.NotAfter)
	}

	// all good
	return cert, nil
}
