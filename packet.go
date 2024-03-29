package fleet

import (
	"encoding/gob"
	"time"

	"github.com/KarpelesLab/rchan"
)

func init() {
	gob.Register(&PacketHandshake{})
	gob.Register(&PacketAnnounce{})
	gob.Register(&PacketRpc{})
	gob.Register(&PacketRpcResponse{})
	gob.Register(&PacketDbRecord{})
	gob.Register(DbStamp{})
	gob.Register(&PacketDbVersions{})
	gob.Register(&PacketDbVersionsEntry{})
	gob.Register(&PacketDbRequest{})
}

type Packet any

type PacketHandshake struct {
	Id       string
	Name     string
	Division string
	Now      time.Time

	Git     string
	Build   string
	Channel string
}

type PacketAnnounce struct {
	Id   string
	Now  time.Time
	Idx  uint64
	NumG uint32 // number of goroutines
	AZ   string
	Meta map[string]any
}

type PacketRpc struct {
	TargetId string
	SourceId string
	Endpoint string
	R        rchan.Id
	Data     any
}

type PacketRpcResponse struct {
	TargetId string
	SourceId string
	R        rchan.Id
	Data     any
	Error    string
	HasError bool
}

type PacketDbRecord struct {
	TargetId string
	SourceId string
	Stamp    DbStamp
	Bucket   []byte // typically "app"
	Key, Val []byte
}

// PacketDbVersions signals what records are available in a peer, typically sent on connection established
type PacketDbVersions struct {
	Info []*PacketDbVersionsEntry
}

type PacketDbVersionsEntry struct {
	Stamp  DbStamp
	Bucket []byte // typically "app"
	Key    []byte
}

// PacketDbRequest requests a specific record, response will be a PacketDbRecord
type PacketDbRequest struct {
	TargetId string
	SourceId string
	Bucket   []byte // typically "app"
	Key      []byte
}
