// Package fleet provides a distributed peer-to-peer communication framework.
package fleet

// Constants defining packet sizes, types, and protocol values
const (
	// PacketMaxLen is the maximum allowed size of a packet (32MB)
	PacketMaxLen = 32 * 1024 * 1024 // 32MB

	// PacketHeaderSize is the size of the packet header (6 bytes)
	// 2 bytes for packet code, 4 bytes for packet length
	PacketHeaderSize = 6

	// PacketMaxBody is the maximum allowed size of the packet body
	PacketMaxBody = PacketMaxLen - PacketHeaderSize

	// Packet type codes
	// The format is:
	// - 0x1xxx: Request packets
	// - 0x3xxx: Response packets
	// - 0xffff: Special legacy format
	// - 0xa000-0xafff: Custom application-defined packets

	// PacketLegacy is used for backward-compatible gob-encoded packets
	PacketLegacy = 0xffff

	// PacketPing is sent to check peer connectivity and measure latency
	PacketPing = 0x1001

	// PacketPong is the response to a ping packet
	PacketPong = 0x3001

	// PacketLockReq is sent to request a distributed lock
	PacketLockReq = 0x1002

	// PacketLockRes is the response to a lock request (Aye or Nay)
	PacketLockRes = 0x3002

	// PacketLockConfirm is sent when a lock is confirmed across the network
	PacketLockConfirm = 0x1003

	// PacketLockRelease is sent when a lock is released
	PacketLockRelease = 0x1004

	// PacketSeed is used to exchange cluster seed data
	PacketSeed = 0x1005

	// PacketRpcBinReq is a binary-format RPC request
	PacketRpcBinReq = 0x1006

	// PacketRpcBinRes is a binary-format RPC response
	PacketRpcBinRes = 0x3006

	// PacketClose is sent when closing a connection gracefully
	PacketClose = 0x1fff

	// PacketCustom is the base value for custom packet types
	// Applications can define their own packet types in this range
	PacketCustom = 0xa000

	// PacketCustomMax is the maximum value for custom packet types
	PacketCustomMax = 0xafff

	// Response values for lock requests
	Aye = 1 // Lock approved
	Nay = 0 // Lock denied
)

// Custom returns a packet ID for a given custom packet type.
// This function ensures that custom packet IDs are within the
// allowed range (0xa000 - 0xafff).
//
// Typically used as:
//
//	var MyCustomPacket = fleet.Custom(0)
//	var MyOtherPacket = fleet.Custom(1)
//
// Parameters:
//   - v: The offset from the base custom packet ID (0-4095)
//
// Returns:
//   - A valid custom packet ID
//
// Panics if the value would exceed the allowed range
func Custom(v uint16) uint16 {
	if v > (PacketCustomMax - PacketCustom) {
		panic("value too high for custom packet")
	}
	return v + PacketCustom
}
