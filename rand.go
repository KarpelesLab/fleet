package fleet

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand"
)

func rand16() uint16 {
	var buf [2]byte
	n, err := io.ReadFull(rand.Reader, buf[:])
	if n == 2 && err == nil {
		return binary.BigEndian.Uint16(buf[:])
	}

	return uint16(mrand.Intn(0xffff))
}
