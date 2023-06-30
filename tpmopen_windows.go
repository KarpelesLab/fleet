package fleet

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

func tpm2open() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}
