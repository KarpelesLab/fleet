package fleet

import (
	"io"
	"log"
	"os"

	"github.com/KarpelesLab/ringbuf"
)

var logbuf *ringbuf.Writer

func initLog() {
	var err error

	logbuf, err = ringbuf.New(1024 * 1024)
	if err == nil {
		log.SetOutput(io.MultiWriter(os.Stdout, logbuf))
	} else {
		log.Printf("[fleet] Failed to setup logbuf: %s", err)
	}
}

func LogTarget() io.Writer {
	return logbuf
}

func LogDmesg(w io.Writer) (int64, error) {
	r := logbuf.Reader()
	defer r.Close()
	return io.Copy(w, r)
}

func shutdownLog() {
	logbuf.Close()
}
