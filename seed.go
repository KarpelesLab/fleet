package fleet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/google/uuid"
)

type seedData struct {
	seed []byte
	Id   uuid.UUID
	ts   time.Time
}

var (
	uuidSeedidSpace = uuid.Must(uuid.Parse(UUID_SEEDID_SPACE))
)

const UUID_SEEDID_SPACE = "da736663-83ec-46ef-9c29-3f9102c5c519"

func makeSeed(s []byte, t time.Time) *seedData {
	seedId := uuid.NewHash(sha3.New256(), uuidSeedidSpace, s, 6) // uuid v6 - this is not in uuid specifications
	return &seedData{
		seed: s,
		Id:   seedId,
		ts:   t,
	}
}

func (a *Agent) initSeed() {
	// check for seed in db (seed is actually shared, but update rule is different from regular record so we use fleet)
	if d, err := a.dbSimpleGet([]byte("fleet"), []byte("seed")); d != nil && err == nil && len(d) > 128 {
		// found seed data in db
		t := time.Time{}
		if t.UnmarshalBinary(d[128:]) == nil {
			// managed to read time too!
			a.seed = makeSeed(d[:128], t)
			log.Printf("[fleet] Initialized with saved cluster seed ID = %s", a.SeedId())
			return
		}
	}

	s := make([]byte, 128)

	// try to load from file (legacy) and remove file (makeSeed will store it on disk)
	if f, err := os.Open("fleet_seed.bin"); err == nil {
		defer f.Close()
		// let's try to read the seed from there?
		n, err := f.Read(s)
		if n == 128 && err == nil {
			// read the timestamp
			tsBin, err := ioutil.ReadAll(f)
			if err == nil {
				t := time.Time{}
				if t.UnmarshalBinary(tsBin) == nil {
					// managed to read time too!
					a.seed = makeSeed(s, t)
					log.Printf("[fleet] Initialized with saved cluster seed ID = %s", a.SeedId())
					if a.seed.WriteToDisk(a) == nil {
						os.Remove("fleet_seed.bin")
					}
					return
				}
			}
		}
	}

	_, err := rand.Read(s)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize fleet seed: %s", err))
	}

	a.seed = makeSeed(s, time.Now())
	a.seed.WriteToDisk(a)

	log.Printf("[fleet] Initialized with cluster seed ID = %s", a.SeedId())
}

func (a *Agent) SeedId() uuid.UUID {
	return a.seed.Id
}

func (s *seedData) WriteToDisk(a *Agent) error {
	ts, err := s.ts.MarshalBinary()
	if err != nil {
		return err
	}

	err = a.dbSimpleSet([]byte("fleet"), []byte("seed"), append(a.seed.seed, ts...))

	if err != nil {
		return err
	}

	return nil
}

func (a *Agent) SeedTlsConfig(c *tls.Config) {
	k := sha256.Sum256(a.seed.seed[32:64])
	// TODO use hmac

	c.SetSessionTicketKeys([][32]byte{k})
}

func (a *Agent) SeedShake128(N []byte) sha3.ShakeHash {
	v := sha3.NewCShake128(N, a.seed.seed)

	return v
}

func (a *Agent) SeedShake256(N []byte) sha3.ShakeHash {
	v := sha3.NewCShake256(N, a.seed.seed)

	return v
}

func (a *Agent) SeedSign(in []byte) []byte {
	hmac := hmac.New(sha3.New256, a.seed.seed)
	hmac.Write(in)
	return hmac.Sum([]byte{})
}

func (a *Agent) SeedCrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.seed.seed[:32])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, in, nil)
	return append(nonce, ciphertext...), nil
}

func (a *Agent) SeedDecrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.seed.seed[:32])
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(in) <= aesgcm.NonceSize() {
		// not enough data
		return nil, errors.New("decrypt: not enough data to decrypt input")
	}

	plaintext, err := aesgcm.Open(nil, in[:aesgcm.NonceSize()], in[aesgcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (a *Agent) seedPacket() *PacketSeed {
	return &PacketSeed{
		Seed: a.seed.seed,
		Time: a.seed.ts,
	}
}

func (a *Agent) handleNewSeed(s []byte, t time.Time) error {
	cur := a.seed
	if t.After(cur.ts) {
		// time is more recent, ignore seed
		return nil
	}
	if bytes.Compare(s, cur.seed) == 0 {
		return nil // same seed already
	}
	if t == cur.ts {
		// not same seed, but same time, compare seeds
		if bytes.Compare(s, cur.seed) > 0 {
			// s is larger, keep seed
			return nil
		}
	}
	a.seed = makeSeed(s, t)
	a.seed.WriteToDisk(a)
	log.Printf("[fleet] Updated seed from peer, new seed ID = %s", a.SeedId())
	return nil
}
