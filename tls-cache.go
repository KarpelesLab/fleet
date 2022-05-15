package fleet

import (
	"crypto/tls"
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
	// TODO
	return c.GetCertificate(nil)
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
