package fleet

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpmKey struct {
	lk  sync.Mutex
	key *client.Key
}

var (
	tpmKeyObject *tpmKey
	tpmKeyInit   sync.Mutex
	tpmKeyOnce   sync.Once
	tpmConn      io.ReadWriteCloser

	tpmKeyTemplate = tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgNull, KeyBits: 0, Mode: 0},
			Sign:      &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID:   tpm2.CurveNISTP256,
		},
	}
)

// This struct is used to marshal and unmarshal an ECDSA signature,
// which consists of two big integers.
type ecdsaSignature struct {
	R, S *big.Int
}

func (a *Agent) getTpmKey() (crypto.Signer, error) {
	return getTpmKey()
}

func getTpmKey() (crypto.Signer, error) {
	tpmKeyInit.Lock()
	defer tpmKeyInit.Unlock()

	if tpmKeyObject != nil {
		return tpmKeyObject, nil
	}

	// the default paths on Linux (/dev/tpmrm0 then /dev/tpm0), will be used
	var err error
	if tpmConn == nil {
		tpmConn, err = tpm2open()
		if err != nil {
			return nil, err
		}
	}

	// only perform this after we got a successful connection to the tpm
	handle := tpmutil.Handle(0x81010001)
	var key *client.Key
	key, err = client.NewCachedKey(tpmConn, tpm2.HandleOwner, tpmKeyTemplate, handle)
	if err != nil {
		return nil, err
	}

	tpmKeyObject = &tpmKey{
		key: key,
	}

	return tpmKeyObject, nil
}

func (k *tpmKey) Public() crypto.PublicKey {
	return k.key.PublicKey()
}

func (k *tpmKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.lk.Lock()
	defer k.lk.Unlock()

	// rand will be ignored because the tpm will do the signature
	sig, err := tpm2.Sign(tpmConn, k.key.Handle(), "", digest, nil, &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256})
	if err != nil {
		return nil, err
	}

	// prepare a structure that can be marshalled by asn1
	ecdsaSig := ecdsaSignature{
		R: sig.ECC.R,
		S: sig.ECC.S,
	}
	return asn1.Marshal(ecdsaSig)
}

func (k *tpmKey) Attest() ([]byte, error) {
	// attempt to generate attestation
	t := time.Now()
	buf := make([]byte, 12)
	binary.BigEndian.PutUint64(buf[:8], uint64(t.Unix()))
	binary.BigEndian.PutUint32(buf[8:], uint32(t.Nanosecond()))

	// grab public key
	pubK := k.Public()
	if pubK == nil {
		return nil, errors.New("no public key")
	}
	pubB, err := x509.MarshalPKIXPublicKey(pubK)
	if err != nil {
		return nil, fmt.Errorf("while marshaling public key: %w", err)
	}

	nonce := buf // append(buf, pubB...)
	_ = pubB

	log.Printf("preparing to attest nonce=%x", nonce)

	// prepare attestation
	key, err := client.GceAttestationKeyECC(tpmConn)
	if err != nil {
		log.Printf("[tpm] failed loading gce key, attempting standard attestation key...")
		key, err = client.AttestationKeyECC(tpmConn)
	}
	if err != nil {
		log.Printf("[tpm] attestation key not available: %s", err)
		return nil, fmt.Errorf("failed loading attestation key: %w", err)
	}
	res, err := key.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %w", err)
	}

	return json.Marshal(res)
}
