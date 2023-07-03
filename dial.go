package fleet

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

func formatAltAddrs(host string, addrs []string, port int) []string {
	// transform CIDR addrs into addr:port
	res := make([]string, 0, len(addrs)+1)

	addrs = append(addrs, "!"+host) // initial ! means we need to wait a bit before connecting

	for _, a := range addrs {
		pos := strings.LastIndexByte(a, '/')
		if pos != -1 {
			a = a[:pos]
		}
		a += ":" + strconv.FormatInt(int64(port), 10)

		res = append(res, a)
	}
	return res
}

// tlsDialAll will dial all the provided hosts at the same time, and return the
// the first one that was successful from the list. If everything fails then
// the last error will be returned, unless everything timed out, in which case
// a timeout error will be returned.
func tlsDialAll(ctx context.Context, timeout time.Duration, addr []string, cfg *tls.Config) (*tls.Conn, error) {
	if len(addr) == 0 {
		return nil, errors.New("no target to connect to")
	}

	// perform dial on as many addrs as passed and return the first one to connect
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx, cancel = context.WithCancel(ctx)
	defer cancel()

	var d net.Dialer
	ch := make(chan *tls.Conn)
	che := make(chan error)

	for _, a := range addr {
		go func(a string) {
			if len(a) > 0 && a[0] == '!' {
				a = a[1:]
				time.Sleep(time.Second) // sleep 1s
			}
			c, err := d.DialContext(ctx, "tcp", a)
			if err != nil {
				select {
				case che <- err:
				case <-ctx.Done():
				}
				return
			}
			tc := tls.Client(c, cfg)
			err = tc.Handshake()
			if err != nil {
				c.Close()
				select {
				case che <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case ch <- tc:
			case <-ctx.Done():
				tc.Close()
			}
		}(a)
	}

	var err error
	for {
		select {
		case c := <-ch:
			// got a connection!
			return c, nil
		case e := <-che:
			err = e
		case <-ctx.Done():
			if err != nil {
				return nil, err
			}
			return nil, ctx.Err()
		}
	}
}
