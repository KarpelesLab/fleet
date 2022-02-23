package fleet

const (
	PacketMaxLen = 32 * 1024 * 1024 // 32MB

	PacketLegacy = 0xffff // legacy gob-encoded packet
	PacketPing   = 0x1001
	PacketPong   = 0x3001
	PacketClose  = 0x1fff

	PacketCustom    = 0xa000 // 0xa000 ~ 0xafff are custom channels
	PacketCustomMax = 0xafff
)

// Custom returns a packet id for a given custom packet
// Typically you will define your custom packet as follow:
//     var MyCustomPacket = fleet.Custom(0)
func Custom(v uint16) uint16 {
	if v > (PacketCustomMax - PacketCustom) {
		panic("value too high for custom packet")
	}
	return v + PacketCustom
}
