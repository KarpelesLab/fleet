package fleet

import (
	"encoding/gob"
	"time"

	"github.com/google/uuid"
)

func init() {
	gob.Register(&PacketHandshake{})
	gob.Register(&PacketAnnounce{})
	gob.Register(&PacketSeed{})
	gob.Register(&PacketPong{})
	gob.Register(&PacketRpc{})
	gob.Register(&PacketRpcResponse{})
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
	Id   uuid.UUID
	Now  time.Time
	Idx  uint64
	NumG int // number of goroutines
	Ip   string
	AZ   string
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

type PacketRpc struct {
	TargetId uuid.UUID
	SourceId uuid.UUID
	Endpoint string
	R        uintptr
	Data     interface{}
}

type PacketRpcResponse struct {
	TargetId uuid.UUID
	SourceId uuid.UUID
	R        uintptr
	Data     interface{}
	Error    string
	HasError bool
}
