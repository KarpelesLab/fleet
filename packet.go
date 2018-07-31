package fleet

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"io"
	"time"

	"github.com/google/uuid"
)

type PacketType uint16

type Packet struct {
	Type    PacketType
	Payload []byte
}

type PacketHandshake struct {
	Id   uuid.UUID
	Name string
	Now  time.Time

	Git   string
	Build string
}

type PacketAnnounce struct {
	Id  uuid.UUID
	Now time.Time
	Idx uint64
	Ip  string
	AZ  string
}

type PacketSeed struct {
	Seed []byte
	Time time.Time
}

type PacketPong struct {
	TargetId uuid.UUID
	SourceId uuid.UUID
	Now      time.Time
}

const (
	P_HANDSHAKE PacketType = iota + 1
	P_ANNOUNCE
	P_PONG
	P_SEED
)

func (p *Packet) MarshalBinary() ([]byte, error) {
	res := &bytes.Buffer{}
	err := p.WriteStream(res)
	return res.Bytes(), err
}

func (p *Packet) WriteStream(res io.Writer) error {
	l := len(p.Payload) + 2
	if l > 0xffff {
		return errors.New("payload too large")
	}

	binary.Write(res, binary.BigEndian, uint16(l))
	binary.Write(res, binary.BigEndian, p.Type)
	res.Write(p.Payload)

	return nil
}

func (p *Packet) UnmarshaBinary(data []byte) error {
	return p.ParseStream(bytes.NewReader(data))
}

func (p *Packet) ParseStream(b io.Reader) error {
	var l uint16
	err := binary.Read(b, binary.BigEndian, &l)
	if err != nil {
		return err
	}

	if l < 2 {
		return errors.New("invalid packet (length < 2)")
	}

	err = binary.Read(b, binary.BigEndian, &p.Type)
	if err != nil {
		return err
	}
	p.Payload = make([]byte, l-2)
	_, err = io.ReadFull(b, p.Payload)
	return err
}

func (p *Packet) SetPayload(o interface{}) error {
	buf := &bytes.Buffer{}
	enc := gob.NewEncoder(buf)
	err := enc.Encode(o)
	p.Payload = buf.Bytes()
	return err
}

func (p *Packet) ReadPayload(o interface{}) error {
	buf := bytes.NewReader(p.Payload)
	dec := gob.NewDecoder(buf)
	return dec.Decode(o)
}
