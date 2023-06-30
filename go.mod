module github.com/KarpelesLab/fleet

go 1.20

require (
	github.com/KarpelesLab/goupd v0.3.1
	github.com/KarpelesLab/jwt v0.1.2
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/ringbuf v0.1.2
	github.com/google/go-tpm v0.9.0
	github.com/google/go-tpm-tools v0.3.13-0.20230620182252-4639ecce2aba
	github.com/google/uuid v1.3.0
	go.etcd.io/bbolt v1.3.7
	golang.org/x/crypto v0.10.0
)

require (
	github.com/google/go-sev-guest v0.6.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.9.0 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
)

retract (
	v0.9.8 // crash on rpc
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
