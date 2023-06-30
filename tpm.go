package fleet

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpmKey struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	lk     sync.Mutex
}

var (
	tpmKeyObject *tpmKey
	tpmKeyOnce   sync.Once
)

// This struct is used to marshal and unmarshal an ECDSA signature,
// which consists of two big integers.
type ecdsaSignature struct {
	R, S *big.Int
}

func (a *Agent) getTpmKey() (crypto.Signer, error) {
	// the default paths on Linux (/dev/tpmrm0 then /dev/tpm0), will be used
	rwc, err := tpm2open()
	if err != nil {
		return nil, err
	}

	// only perform this after we got a successful connection to the tpm
	tpmKeyOnce.Do(func() {
		tpmKeyObject = &tpmKey{
			rwc:    rwc,
			handle: tpmutil.Handle(0x81010001),
		}
	})

	return tpmKeyObject, nil
}

func (k *tpmKey) Public() crypto.PublicKey {
	k.lk.Lock()
	defer k.lk.Unlock()

	pub, _, _, err := tpm2.ReadPublic(k.rwc, k.handle)
	if err != nil {
		// attempt to create key since fetching failed
		// chatgpt says the error when a handle is not found is "handle 1 unsupported" but that sounds suspicious
		// Microsoft simulator returns: handle 1, error code 0xb : the handle is not correct for the use
		log.Printf("[tpm] failed to fetch key from tpm, will attempt to create one. Error: %s", err)
		err = k.createKey()
		if err == nil {
			// creation succeeded, try to fetch it again
			pub, _, _, err = tpm2.ReadPublic(k.rwc, k.handle)
		}
	}

	if err == nil {
		pubk, err := pub.Key()
		if err != nil {
			log.Printf("[tpm] failed to decode public key from tpm: %s", err)
			return nil
		}
		return pubk
	} else {
		log.Printf("[tpm] failed to read public key from tpm: %s", err)
		return nil
	}
}

func (k *tpmKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.lk.Lock()
	defer k.lk.Unlock()

	// rand will be ignored because the tpm will do the signature

	sig, err := tpm2.Sign(k.rwc, k.handle, "", digest, nil, &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256})
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

func (k *tpmKey) createKey() error {
	// Define the template for the key
	public := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgNull, KeyBits: 0, Mode: 0},
			Sign:      &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgSHA256},
			CurveID:   tpm2.CurveNISTP256,
		},
	}

	// Define the parameters for the key
	params := tpm2.PCRSelection{}

	// Create the key
	// func CreatePrimary(rw io.ReadWriter, owner tpmutil.Handle, sel PCRSelection, parentPassword, ownerPassword string, p Public) (tpmutil.Handle, crypto.PublicKey, error)
	handle, _, err := tpm2.CreatePrimary(k.rwc, tpm2.HandleOwner, params, "", "", public)
	if err != nil {
		return fmt.Errorf("failed creating ECC key: %w", err)
	}

	// make it persistant
	err = tpm2.EvictControl(k.rwc, "", tpm2.HandleOwner, handle, k.handle)
	if err != nil {
		return fmt.Errorf("failed to persist key: %w", err)
	}

	return nil
}
