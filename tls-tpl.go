package fleet

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
)

// templates for tls

var tplCAcrt = x509.Certificate{
	BasicConstraintsValid: true,
	IsCA:                  true,
	SerialNumber:          big.NewInt(1),
	Issuer:                pkix.Name{CommonName: "Local Fleet CA"},
	Subject:               pkix.Name{CommonName: "Local Fleet CA"},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	MaxPathLen:            1,
}

var tplUsrCrt = x509.Certificate{
	BasicConstraintsValid: true,
	IsCA:                  false,
	Issuer:                pkix.Name{CommonName: "Local Fleet CA"},
	KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment | x509.KeyUsageKeyEncipherment,
	MaxPathLen:            2,
}
