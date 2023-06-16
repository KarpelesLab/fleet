package fleet

const (
	PacketMaxLen     = 32 * 1024 * 1024 // 32MB
	PacketHeaderSize = 6                // 2 bytes packet code, 4 bytes packet length
	PacketMaxBody    = PacketMaxLen - PacketHeaderSize

	PacketLegacy      = 0xffff // legacy gob-encoded packet
	PacketPing        = 0x1001
	PacketPong        = 0x3001
	PacketLockReq     = 0x1002 // request for lock
	PacketLockRes     = 0x3002 // response (aye or nay)
	PacketLockConfirm = 0x1003 // lock is confirmed (or re-confirmed) → status = 1
	PacketLockRelease = 0x1004 // lock is released
	PacketSeed        = 0x1005 // seed data
	PacketRpcBinReq   = 0x1006
	PacketRpcBinRes   = 0x3006
	PacketClose       = 0x1fff

	PacketCustom    = 0xa000 // 0xa000 ~ 0xafff are custom channels
	PacketCustomMax = 0xafff

	Aye = 1
	Nay = 0
)

// Custom returns a packet id for a given custom packet
// Typically you will define your custom packet as follow:
//
//	var MyCustomPacket = fleet.Custom(0)
func Custom(v uint16) uint16 {
	if v > (PacketCustomMax - PacketCustom) {
		panic("value too high for custom packet")
	}
	return v + PacketCustom
}
