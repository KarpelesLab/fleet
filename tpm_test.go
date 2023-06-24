package fleet

// we use fleet package for testing tpm in order to access internals
import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestTpm(t *testing.T) {
	// initialize tpm simulator
	sim, err := simulator.GetWithFixedSeedInsecure(42)
	if err != nil {
		t.Fatalf("could not initialize TPM simulator: %s", err)
		return
	}

	mfg, err := tpm2.GetManufacturer(sim)
	if err == nil {
		log.Printf("TPM manufacturer: %s", mfg)
	} else {
		log.Printf("Failed to get manufacturer: %s", err)
	}

	ktest := &tpmKey{
		rwc:    sim,
		handle: tpmutil.Handle(0x81010001),
	}

	// get public key
	pubKey := ktest.Public()
	if pubKey == nil {
		t.Fatalf("could not get public key")
		return
	}

	pubBin, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("could not marshal public key: %s", err)
		return
	}
	log.Printf("public key = %s", base64.RawURLEncoding.EncodeToString(pubBin))

	// attempt to generate a x509 certificate
	tplCA := tplCAcrt
	tplCA.NotBefore = time.Now()
	tplCA.NotAfter = tplCA.NotBefore.Add(10 * 365 * 24 * time.Hour) // +10 years (more or less)

	ca_crt_der, err := x509.CreateCertificate(rand.Reader, &tplCA, &tplCA, pubKey, ktest)
	if err != nil {
		t.Fatalf("could not sign certificate: %s", err)
		return
	}

	ca_crt, err := x509.ParseCertificate(ca_crt_der)
	if err != nil {
		t.Fatalf("could not parse certificate: %s", err)
		return
	}
	ca_crt_pem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca_crt_der})

	if !reflect.DeepEqual(ca_crt.PublicKey, pubKey) {
		t.Errorf("public key is different")
	}

	log.Printf("generated CA:\n%s", ca_crt_pem)

	err = ca_crt.CheckSignatureFrom(ca_crt)
	if err != nil {
		t.Errorf("failed to check signature: %s", err)
	}
}
