package fleet

import (
	"encoding/gob"
	"time"
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
	Id       string
	Name     string
	Division string
	Now      time.Time

	Git   string
	Build string
}

type PacketAnnounce struct {
	Id   string
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
	TargetId string
	SourceId string
	Now      time.Time
}

type PacketRpc struct {
	TargetId string
	SourceId string
	Endpoint string
	R        uintptr
	Data     interface{}
}

type PacketRpcResponse struct {
	TargetId string
	SourceId string
	R        uintptr
	Data     interface{}
	Error    string
	HasError bool
}
