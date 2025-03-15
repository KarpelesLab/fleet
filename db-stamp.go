// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

import (
	"encoding/binary"
	"errors"
	"time"
)

// DbStamp represents a timestamp for database entries.
// It's used to track when entries were created or modified and to
// resolve conflicts when the same key is modified on different peers.
//
// DbStamp is a type alias for time.Time with specialized binary serialization
// that is consistent across all peers in the fleet.
type DbStamp time.Time

// DbNow returns the current time as a DbStamp.
// This is used when creating or updating database entries.
//
// Returns:
//   - A DbStamp representing the current time
func DbNow() DbStamp {
	return DbStamp(time.Now())
}

// DbZero returns the Unix epoch (Jan 1, 1970) as a DbStamp.
// This is used as a default or initial value.
//
// Returns:
//   - A DbStamp representing the Unix epoch
func DbZero() DbStamp {
	return DbStamp(time.Unix(0, 0))
}

// Unix returns the DbStamp as Unix time (seconds since epoch).
//
// Returns:
//   - Seconds since Unix epoch
func (t DbStamp) Unix() int64 {
	return time.Time(t).Unix()
}

// UnixNano returns the DbStamp as Unix time in nanoseconds.
//
// Returns:
//   - Nanoseconds since Unix epoch
func (t DbStamp) UnixNano() int64 {
	return time.Time(t).UnixNano()
}

// String returns a human-readable representation of the timestamp.
//
// Returns:
//   - String representation of the timestamp
func (t DbStamp) String() string {
	return time.Time(t).String()
}

// Bytes returns a binary representation of the timestamp.
// This is used for network transmission and storage.
// The format is 16 bytes:
// - 8 bytes: seconds since epoch (big-endian uint64)
// - 8 bytes: nanoseconds part (big-endian uint64)
//
// Returns:
//   - Binary representation of the timestamp
func (t DbStamp) Bytes() []byte {
	r := make([]byte, 16)
	binary.BigEndian.PutUint64(r[:8], uint64(time.Time(t).Unix()))
	binary.BigEndian.PutUint64(r[8:], uint64(time.Time(t).Nanosecond()))
	return r
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// This allows DbStamp to be used with binary encoding functions.
//
// Returns:
//   - Binary representation of the timestamp
//   - Nil error (this method never fails)
func (t DbStamp) MarshalBinary() ([]byte, error) {
	return t.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// This allows DbStamp to be reconstructed from its binary representation.
//
// Parameters:
//   - data: Binary representation of a timestamp (16 bytes)
//
// Returns:
//   - An error if unmarshaling fails, nil otherwise
func (t *DbStamp) UnmarshalBinary(data []byte) error {
	// Validate data length
	if len(data) != 16 {
		return errors.New("invalid DbStamp unmarshal: bad data length")
	}

	// Extract seconds and nanoseconds
	ut := int64(binary.BigEndian.Uint64(data[:8]))
	un := int64(binary.BigEndian.Uint64(data[8:]))

	// Reconstruct the time
	*t = DbStamp(time.Unix(ut, un))
	return nil
}

// After compares two DbStamps and returns whether this timestamp
// is after the other one. This is used for conflict resolution.
//
// Parameters:
//   - t2: The timestamp to compare against
//
// Returns:
//   - true if this timestamp is after t2, false otherwise
func (t DbStamp) After(t2 DbStamp) bool {
	return time.Time(t).After(time.Time(t2))
}

// GobEncode implements the gob.GobEncoder interface.
// This allows DbStamp to be used with gob encoding.
//
// Returns:
//   - Gob-encoded representation of the timestamp
//   - An error if encoding fails
func (t DbStamp) GobEncode() ([]byte, error) {
	return time.Time(t).GobEncode()
}

// GobDecode implements the gob.GobDecoder interface.
// This allows DbStamp to be reconstructed from its gob encoding.
//
// Parameters:
//   - data: Gob-encoded representation of a timestamp
//
// Returns:
//   - An error if decoding fails, nil otherwise
func (t *DbStamp) GobDecode(data []byte) error {
	return (*time.Time)(t).GobDecode(data)
}
