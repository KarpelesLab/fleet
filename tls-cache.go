package fleet

import (
	"crypto/tls"
	"log"
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
	if err != nil {
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

	c.crt, c.err = c.loadCert()
	if c.err != nil {
		log.Printf("[tls] Failed to fetch %s certificate: %s", c.k, c.err)
	}

	return c.crt, c.err
}

func (c *crtCache) loadCert() (*tls.Certificate, error) {
	crt, err := c.a.dbFleetLoad(c.k + ":crt")
	if err != nil {
		return nil, err
	}
	key, err := c.a.dbFleetGet(c.k + ":key")
	if err != nil {
		return nil, err
	}

	res, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
