package fleet

const (
	PacketMaxLen = 1024 * 1024 // 1MB

	PacketLegacy = 0xffff // legacy gob-encoded packet
	PacketPing   = 0x1001
	PacketAlive  = 0x1002
	PacketPong   = 0x3001
	PacketClose  = 0x1fff
	PacketCustom = 0xa000 // 0xa000 ~ 0xafff are custom channels
	MaxCustom    = 0xafff
)
