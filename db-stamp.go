package fleet

import (
	"encoding/binary"
	"errors"
	"time"
)

// a timestamp for db
type DbStamp time.Time

func DbNow() DbStamp {
	return DbStamp(time.Now())
}

func DbZero() DbStamp {
	return DbStamp(time.Unix(0, 0))
}

func (t DbStamp) Unix() int64 {
	return time.Time(t).Unix()
}

func (t DbStamp) UnixNano() int64 {
	return time.Time(t).UnixNano()
}

func (t DbStamp) String() string {
	return time.Time(t).String()
}

func (t DbStamp) Bytes() []byte {
	r := make([]byte, 16)
	binary.BigEndian.PutUint64(r[:8], uint64(time.Time(t).Unix()))
	binary.BigEndian.PutUint64(r[8:], uint64(time.Time(t).Nanosecond()))
	return r
}

func (t DbStamp) MarshalBinary() ([]byte, error) {
	return t.Bytes(), nil
}

func (t *DbStamp) UnmarshalBinary(data []byte) error {
	// read a timestamp (inverse of MarshalBinary)
	if len(data) != 16 {
		return errors.New("invalid DbStamp unmarshal: bad data length")
	}

	ut := int64(binary.BigEndian.Uint64(data[:8]))
	un := int64(binary.BigEndian.Uint64(data[8:]))
	*t = DbStamp(time.Unix(ut, un))
	return nil
}

func (t DbStamp) After(t2 DbStamp) bool {
	return time.Time(t).After(time.Time(t2))
}

func (t DbStamp) GobEncode() ([]byte, error) {
	return time.Time(t).GobEncode()
}

func (t *DbStamp) GobDecode(data []byte) error {
	return (*time.Time)(t).GobDecode(data)
}
