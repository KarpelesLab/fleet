package fleet

import (
	"bytes"
	"encoding/binary"
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

func (t DbStamp) MarshalBinary() ([]byte, error) {
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, time.Time(t).Unix())
	if err != nil {
		return nil, err
	}
	err = binary.Write(&b, binary.BigEndian, int64(time.Time(t).Nanosecond()))
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (t *DbStamp) UnmarshalBinary(data []byte) error {
	// read a timestamp (inverse of MarshalBinary)
	r := bytes.NewReader(data)
	var ut, un int64
	err := binary.Read(r, binary.BigEndian, &ut)
	if err != nil {
		return err
	}
	err = binary.Read(r, binary.BigEndian, &un)
	if err != nil {
		return err
	}
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
