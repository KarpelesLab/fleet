package fleet

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"
	"io"
	"log"
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
	_, err := rand.Read(s)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize fleet seed: %s", err))
	}

	seed = makeSeed(s, time.Now())

	log.Printf("[fleet] Initialized with cluster seed ID = %s", SeedId())
}

func SeedId() uuid.UUID {
	return seed.Id
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

	plaintext, err := aesgcm.Open(nil, in[:aesgcm.NonceSize()], in[aesgcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func seedPacket() *Packet {
	pkt := &Packet{Type: P_SEED}
	pkt.SetPayload(PacketSeed{
		Seed: seed.seed,
		Time: seed.ts,
	})
	return pkt
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
	log.Printf("[fleet] Updated seed from peer, new seed ID = %s", SeedId())
	return nil
}
