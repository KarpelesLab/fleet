module github.com/KarpelesLab/fleet

go 1.20

require (
	github.com/KarpelesLab/goupd v0.3.2
	github.com/KarpelesLab/jwt v0.1.4
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/ringbuf v0.1.2
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.4.2
	github.com/google/uuid v1.4.0
	go.etcd.io/bbolt v1.3.8
	golang.org/x/crypto v0.19.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-sev-guest v0.9.3 // indirect
	github.com/google/go-tdx-guest v0.2.3-0.20231011100059-4cf02bed9d33 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.17.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

retract (
	v0.9.8 // crash on rpc
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
