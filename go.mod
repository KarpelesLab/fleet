module github.com/KarpelesLab/fleet

go 1.22.2

require (
	github.com/KarpelesLab/cloudinfo v0.1.6
	github.com/KarpelesLab/goupd v0.4.4
	github.com/KarpelesLab/jwt v0.1.11
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/ringbuf v0.1.2
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/uuid v1.6.0
	go.etcd.io/bbolt v1.3.10
	golang.org/x/crypto v0.24.0
)

require (
	github.com/KarpelesLab/cryptutil v0.2.7 // indirect
	github.com/KarpelesLab/tpmlib v0.1.2 // indirect
	github.com/ModChain/edwards25519 v1.0.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-configfs-tsm v0.2.2 // indirect
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

retract (
	v0.9.8 // crash on rpc
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
