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

var (
	seed []byte
	ts   time.Time
)

const UUID_SEEDID_SPACE = "da736663-83ec-46ef-9c29-3f9102c5c519"

func initSeed() {
	seed = make([]byte, 128)
	_, err := rand.Read(seed)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize fleet seed: %s", err))
	}
	ts = time.Now()

	log.Printf("[fleet] Initialized with cluster seed ID = %s", SeedId())
}

func SeedUuid() uuid.UUID {
	// return an id for the seed
	space := uuid.Must(uuid.Parse(UUID_SEEDID_SPACE))
	uuid := uuid.NewHash(sha3.New256(), space, seed, 6) // uuid v6 - this is not in uuid specifications
	return uuid
}

func SeedId() string {
	// return an id for the seed
	space := uuid.Must(uuid.Parse(UUID_SEEDID_SPACE))
	uuid := uuid.NewHash(sha3.New256(), space, seed, 6) // uuid v6 - this is not in uuid specifications
	return uuid.String()
}

func SeedPacket() *Packet {
	pkt := &Packet{Type: P_SEED}
	pkt.SetPayload(PacketSeed{
		Seed: seed,
		Time: ts,
	})
	return pkt
}

func handleNewSeed(s []byte, t time.Time) error {
	if t.After(ts) {
		// time is more recent, ignore seed
		return nil
	}
	if bytes.Compare(s, seed) == 0 {
		return nil // same seed already
	}
	if t == ts {
		// not same seed, but same time, compare seeds
		if bytes.Compare(s, seed) > 0 {
			// s is larger, keep seed
			return nil
		}
	}
	copy(seed, s)
	log.Printf("[fleet] Updated seed from peer, new seed ID = %s", SeedId())
	return nil
}
