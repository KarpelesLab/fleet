// Package fleet provides a distributed peer-to-peer communication framework.
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
	"log/slog"
	"os"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/google/uuid"
)

// seedData represents a cluster-wide shared secret.
// The seed is used to create a unique cluster identity, authenticate peers,
// and provide encryption for secure communication.
//
// The seed is synchronized across all peers in the fleet using the newest-wins
// policy, where newer timestamps take precedence.
type seedData struct {
	seed []byte    // Raw seed data (128 bytes of cryptographic randomness)
	Id   uuid.UUID // UUID derived from the seed for identification
	ts   time.Time // Timestamp when the seed was created
}

var (
	// UUID namespace for seed IDs
	uuidSeedidSpace = uuid.Must(uuid.Parse(UUID_SEEDID_SPACE))
)

// UUID namespace for generating deterministic seed IDs
const UUID_SEEDID_SPACE = "da736663-83ec-46ef-9c29-3f9102c5c519"

// makeSeed creates a new seedData instance from raw seed bytes and a timestamp.
// It generates a deterministic UUID from the seed for identification purposes.
//
// Parameters:
//   - s: Raw seed data (128 bytes)
//   - t: Timestamp for the seed
//
// Returns:
//   - A new seedData instance
func makeSeed(s []byte, t time.Time) *seedData {
	// Generate a deterministic UUID from the seed using SHA3-256
	// UUID v6 is used (not in UUID spec, but provides deterministic output)
	seedId := uuid.NewHash(sha3.New256(), uuidSeedidSpace, s, 6)

	return &seedData{
		seed: s,      // Raw seed data
		Id:   seedId, // UUID derived from seed
		ts:   t,      // Timestamp
	}
}

// initSeed initializes the agent's seed data.
// The seed is loaded from the database if available, or from a legacy file,
// or generated fresh if neither exists.
//
// The seed serves as a cluster-wide shared secret that all peers in the
// same fleet will synchronize to the newest one.
func (a *Agent) initSeed() {
	// Try to load seed from database
	// The seed is stored in the "fleet" bucket for internal data
	if d, err := a.dbSimpleGet([]byte("fleet"), []byte("seed")); d != nil && err == nil && len(d) > 128 {
		// Found seed data in database
		t := time.Time{}
		if t.UnmarshalBinary(d[128:]) == nil {
			// Successfully parsed the timestamp
			a.seed = makeSeed(d[:128], t)
			slog.Debug(fmt.Sprintf("[fleet] Initialized with saved cluster seed ID = %s", a.SeedId()),
				"event", "fleet:seed:init")
			return
		}
	}

	// Prepare buffer for seed (128 bytes of randomness)
	s := make([]byte, 128)

	// Legacy: Try to load from file (older versions stored the seed in a file)
	if f, err := os.Open("fleet_seed.bin"); err == nil {
		defer f.Close()

		// Try to read the seed data
		n, err := f.Read(s)
		if n == 128 && err == nil {
			// Read the timestamp that follows the seed
			tsBin, err := io.ReadAll(f)
			if err == nil {
				t := time.Time{}
				if t.UnmarshalBinary(tsBin) == nil {
					// Successfully loaded from file
					a.seed = makeSeed(s, t)
					slog.Debug(fmt.Sprintf("[fleet] Initialized with saved cluster seed ID = %s", a.SeedId()),
						"event", "fleet:seed:init")

					// Migrate to database storage and remove the file
					if a.seed.WriteToDisk(a) == nil {
						os.Remove("fleet_seed.bin")
					}
					return
				}
			}
		}
	}

	// No existing seed found, generate a new one
	_, err := io.ReadFull(rand.Reader, s)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize fleet seed: %s", err))
	}

	// Create and save the new seed
	a.seed = makeSeed(s, time.Now())
	a.seed.WriteToDisk(a)

	slog.Debug(fmt.Sprintf("[fleet] Initialized with cluster seed ID = %s", a.SeedId()),
		"event", "fleet:seed:new")
}

// SeedId returns the UUID identifier for the cluster seed.
// This is a deterministic UUID generated from the seed data.
//
// Returns:
//   - UUID derived from the seed
func (a *Agent) SeedId() uuid.UUID {
	return a.seed.Id
}

// WriteToDisk persists the seed data to the database.
// This saves both the raw seed and its timestamp for later retrieval.
//
// Parameters:
//   - a: The agent to use for database access
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (s *seedData) WriteToDisk(a *Agent) error {
	// Marshal the timestamp to binary form
	ts, err := s.ts.MarshalBinary()
	if err != nil {
		return err
	}

	// Store seed + timestamp in the fleet bucket
	err = a.dbSimpleSet([]byte("fleet"), []byte("seed"), append(s.seed, ts...))
	if err != nil {
		return err
	}

	return nil
}

// SeedTlsConfig configures a TLS config object with session ticket keys
// derived from the seed. This ensures all nodes in the fleet use the same
// ticket keys, allowing session resumption between different nodes.
//
// Parameters:
//   - c: The TLS config to modify
func (a *Agent) SeedTlsConfig(c *tls.Config) {
	// Generate a key from part of the seed
	k := sha256.Sum256(a.seed.seed[32:64])
	// TODO: use hmac for better security

	// Set the session ticket keys
	c.SetSessionTicketKeys([][32]byte{k})
}

// SeedShake128 creates a new cSHAKE-128 hash instance customized with the seed.
// This provides a deterministic pseudo-random function that's consistent
// across all peers with the same seed.
//
// Parameters:
//   - N: The function name/customization string
//
// Returns:
//   - A ShakeHash instance for generating deterministic output
func (a *Agent) SeedShake128(N []byte) sha3.ShakeHash {
	return sha3.NewCShake128(N, a.seed.seed)
}

// SeedShake256 creates a new cSHAKE-256 hash instance customized with the seed.
// This provides a deterministic pseudo-random function that's consistent
// across all peers with the same seed, with higher security than SeedShake128.
//
// Parameters:
//   - N: The function name/customization string
//
// Returns:
//   - A ShakeHash instance for generating deterministic output
func (a *Agent) SeedShake256(N []byte) sha3.ShakeHash {
	return sha3.NewCShake256(N, a.seed.seed)
}

// SeedSign creates an HMAC signature for the input data using SHA3-256.
// This is used to authenticate messages between peers.
//
// Parameters:
//   - in: The data to sign
//
// Returns:
//   - The HMAC signature
func (a *Agent) SeedSign(in []byte) []byte {
	h := hmac.New(sha3.New256, a.seed.seed)
	h.Write(in)
	return h.Sum([]byte{})
}

// SeedCrypt encrypts data using AES-GCM with a key derived from the seed.
// This provides authenticated encryption for sensitive data.
//
// Parameters:
//   - in: The plaintext data to encrypt
//
// Returns:
//   - The encrypted data (nonce + ciphertext)
//   - An error if encryption fails
func (a *Agent) SeedCrypt(in []byte) ([]byte, error) {
	// Create a new AES cipher using the first 32 bytes of the seed as the key
	block, err := aes.NewCipher(a.seed.seed[:32])
	if err != nil {
		return nil, err
	}

	// Create a GCM (Galois/Counter Mode) instance
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate the plaintext
	ciphertext := aesgcm.Seal(nil, nonce, in, nil)

	// Return nonce + ciphertext
	return append(nonce, ciphertext...), nil
}

// SeedDecrypt decrypts data that was encrypted with SeedCrypt.
// This verifies and decrypts data encrypted by any peer with the same seed.
//
// Parameters:
//   - in: The encrypted data (nonce + ciphertext)
//
// Returns:
//   - The decrypted plaintext
//   - An error if decryption fails
func (a *Agent) SeedDecrypt(in []byte) ([]byte, error) {
	// Create a new AES cipher using the first 32 bytes of the seed as the key
	block, err := aes.NewCipher(a.seed.seed[:32])
	if err != nil {
		return nil, err
	}

	// Create a GCM (Galois/Counter Mode) instance
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check if the input is long enough to contain a nonce
	if len(in) <= aesgcm.NonceSize() {
		return nil, errors.New("decrypt: not enough data to decrypt input")
	}

	// Extract nonce and decrypt+verify the ciphertext
	plaintext, err := aesgcm.Open(nil, in[:aesgcm.NonceSize()], in[aesgcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// seedData returns a binary representation of the seed with its timestamp.
// This is used for network transmission between peers.
//
// Returns:
//   - A byte slice containing the seed timestamp and raw seed data
func (a *Agent) seedData() []byte {
	// Convert the timestamp to binary form
	ts := DbStamp(a.seed.ts).Bytes()
	// Return timestamp + seed
	return append(ts, a.seed.seed...)
}

// handleNewSeed processes a seed received from another peer.
// The fleet uses an oldest-wins policy for seed synchronization:
// - If the received seed is newer than our current seed, we keep our seed
// - If the received seed is older than our current seed, we adopt the received seed
// - If they have the same timestamp, the seed with the larger binary value wins
//
// Parameters:
//   - s: The raw seed data received from a peer
//   - t: The timestamp of the received seed
//
// Returns:
//   - An error if the operation fails, nil otherwise
func (a *Agent) handleNewSeed(s []byte, t time.Time) error {
	cur := a.seed

	// Check if the received seed is newer than our current seed
	if t.After(cur.ts) {
		// Our seed is older, so we keep our seed
		return nil
	}

	// Check if it's the same seed
	if bytes.Equal(s, cur.seed) {
		return nil // Already have this seed
	}

	// If timestamps are identical, compare the raw seed values
	if t == cur.ts {
		// Tie-breaker: compare the raw seed values
		if bytes.Compare(s, cur.seed) > 0 {
			// Received seed is larger, keep our seed
			return nil
		}
	}

	// The received seed takes precedence, adopt it
	a.seed = makeSeed(s, t)
	a.seed.WriteToDisk(a)
	slog.Info(fmt.Sprintf("[fleet] Updated seed from peer, new seed ID = %s", a.SeedId()),
		"event", "fleet:seed:update")
	return nil
}
