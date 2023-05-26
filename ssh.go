package fleet

import (
	"io/fs"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type quasiConn struct {
	ssh.Channel
	p *Peer
}

func (q *quasiConn) LocalAddr() net.Addr {
	return q.p.ssh.LocalAddr()
}

func (q *quasiConn) RemoteAddr() net.Addr {
	return q.p.ssh.RemoteAddr()
}

func (q *quasiConn) SetDeadline(t time.Time) error {
	return fs.ErrInvalid
}

func (q *quasiConn) SetReadDeadline(t time.Time) error {
	return fs.ErrInvalid
}

func (q *quasiConn) SetWriteDeadline(t time.Time) error {
	return fs.ErrInvalid
}
