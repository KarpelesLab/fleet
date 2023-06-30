package fleet

import (
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
)

func tpm2open() (io.ReadWriteCloser, error) {
	rwc, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		rwc, err = tpm2.OpenTPM("/dev/tpm0")
	}
	return rwc, err
}
