package fleet

import (
	"crypto"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type tpmKey struct {
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
}

// This struct is used to marshal and unmarshal an ECDSA signature,
// which consists of two big integers.
type ecdsaSignature struct {
	R, S *big.Int
}

func (a *Agent) getTpmKey() (crypto.Signer, error) {
	// the default paths on Linux (/dev/tpmrm0 then /dev/tpm0), will be used
	rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		rwc, err = tpm2.OpenTPM("/dev/tpm0")
	}
	if err != nil {
		return nil, err
	}

	key := &tpmKey{
		rwc:    rwc,
		handle: tpmutil.Handle(0x81010001),
	}

	return key, nil
}

func (k *tpmKey) Public() crypto.PublicKey {
	pub, _, _, err := tpm2.ReadPublic(k.rwc, k.handle)
	if err != nil {
		// attempt to create key since fetching failed
		// chatgpt says the error when a handle is not found is "handle 1 unsupported" but that sounds suspicious
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
	// rand will be ignored because the tpm will do the signature
	// digest will require to be using sha256
	if opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("unsupported hashing algo")
	}

	// should we pass Hash: AlgNull or Hash: AlgSha256?
	sig, err := tpm2.Sign(k.rwc, k.handle, "", digest, nil, &tpm2.SigScheme{Alg: tpm2.AlgECDSA, Hash: tpm2.AlgNull})
	if err != nil {
		return nil, err
	}

	ecdsaSig := ecdsaSignature{
		R: sig.ECC.R, // the X value is used as 'R' in ECDSA
		S: sig.ECC.S, // the Y value is used as 'S' in ECDSA
	}
	return asn1.Marshal(ecdsaSig)
}

func (k *tpmKey) createKey() error {
	// Define the template for the key
	public := tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
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
