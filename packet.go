package fleet

import (
	"encoding/gob"
	"time"

	"github.com/google/uuid"
)

func regPackets() {
	gob.Register(&PacketHandshake{})
	gob.Register(&PacketAnnounce{})
	gob.Register(&PacketSeed{})
	gob.Register(&PacketPong{})
}

type Packet interface{}

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
