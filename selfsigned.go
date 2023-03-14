package fleet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"sync"
	"time"
)

var (
	certSelfKey   *ecdsa.PrivateKey
	certSelfLock  sync.Mutex
	certSelfCache map[string]*tls.Certificate
)

// GetSelfsignedCertificate is a utility function that returns a self-signed certificate for any given host name
//
// All generated certificates are cached, and calling this method multiple times with the same name will return
// the same certificate for a few days, and will then generate a new certificate.
func GetSelfsignedCertificate(n string) (*tls.Certificate, error) {
	certSelfLock.Lock()
	defer certSelfLock.Unlock()

	// ensure we have a key for self-signing
	if certSelfKey == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			// should not happen
			return nil, fmt.Errorf("failed to generate ECDSA key for self-signed certificate: %w", err)
		}
		certSelfKey = k
		certSelfCache = make(map[string]*tls.Certificate)
	}

	if crt, ok := certSelfCache[n]; ok {
		// we already generated this certificate before, check expiration
		if time.Until(crt.Leaf.NotAfter) > 24*time.Hour {
			return crt, nil
		}
	}

	rnd := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, rnd)
	if err != nil {
		return nil, err
	}

	sn := big.NewInt(0)
	sn = sn.SetBytes(rnd)

	ctpl := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		Version:               1,
		SerialNumber:          sn,

		Issuer:     pkix.Name{CommonName: n},
		Subject:    pkix.Name{CommonName: n},
		KeyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen: 1,
		DNSNames:   []string{n},
	}

	now := time.Now()
	ctpl.NotBefore = now.Add(-1 * time.Minute)
	ctpl.NotAfter = now.Add(7 * 24 * time.Hour)

	crt, err := x509.CreateCertificate(rand.Reader, ctpl, ctpl, certSelfKey.Public(), certSelfKey)
	if err != nil {
		return nil, err
	}

	// parse main certificate
	pc, err := x509.ParseCertificate(crt)
	if err != nil {
		return nil, err
	}

	tlsCrt := &tls.Certificate{
		Certificate: [][]byte{crt},
		PrivateKey:  certSelfKey,
		Leaf:        pc,
	}

	if len(certSelfCache) > 1024 {
		// cache is growing too much, reset it
		certSelfCache = make(map[string]*tls.Certificate)
	}

	certSelfCache[n] = tlsCrt

	return tlsCrt, nil
}
