package fleet

import (
	"bytes"
	"crypto/rand"
	"fmt"
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
