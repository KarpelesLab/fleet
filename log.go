package fleet

import (
	"io"
	"log"
	"os"

	"github.com/KarpelesLab/ringbuf"
)

func (a *AgentObj) initLog() {
	var err error

	a.logbuf, err = ringbuf.New(1024 * 1024)
	if err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, a.logbuf))
	} else {
		log.Printf("[fleet] Failed to setup logbuf: %s", err)
	}
}

func (a *AgentObj) LogTarget() io.Writer {
	return a.logbuf
}

func (a *AgentObj) LogDmesg(w io.Writer) (int64, error) {
	r := a.logbuf.Reader()
	defer r.Close()
	return io.Copy(w, r)
}

func (a *AgentObj) shutdownLog() {
	// return output to normal first
	log.SetOutput(os.Stderr)
	a.logbuf.Close()
}
