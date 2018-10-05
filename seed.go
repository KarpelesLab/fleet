package fleet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
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
	// use a pointer for atomic seed details update
	seed *seedData

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

func initSeed() {
	s := make([]byte, 128)

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
					seed = makeSeed(s, t)
					log.Printf("[fleet] Initialized with saved cluster seed ID = %s", SeedId())
					return
				}
			}
		}
	}

	_, err := rand.Read(s)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize fleet seed: %s", err))
	}

	seed = makeSeed(s, time.Now())
	seed.WriteToDisk()

	log.Printf("[fleet] Initialized with cluster seed ID = %s", SeedId())
}

func SeedId() uuid.UUID {
	return seed.Id
}

func (s *seedData) WriteToDisk() error {
	ts, err := s.ts.MarshalBinary()
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("fleet_seed.bin~", append(seed.seed, ts...), 0600)

	if err != nil {
		return err
	}

	os.Rename("fleet_seed.bin~", "fleet_seed.bin")

	return nil
}

func SeedTlsConfig(c *tls.Config) {
	copy(c.SessionTicketKey[:], seed.seed[32:64])
}

func SeedSign(in []byte) []byte {
	hmac := hmac.New(sha3.New256, seed.seed)
	hmac.Write(in)
	return hmac.Sum([]byte{})
}

func SeedCrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(seed.seed[:32])
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

func SeedDecrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(seed.seed[:32])
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

func seedPacket() *PacketSeed {
	return &PacketSeed{
		Seed: seed.seed,
		Time: seed.ts,
	}
}

func handleNewSeed(s []byte, t time.Time) error {
	cur := seed
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
	seed = makeSeed(s, t)
	seed.WriteToDisk()
	log.Printf("[fleet] Updated seed from peer, new seed ID = %s", SeedId())
	return nil
}
