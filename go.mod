module github.com/KarpelesLab/fleet

go 1.24

toolchain go1.24.0

require (
	github.com/KarpelesLab/cloudinfo v0.1.7
	github.com/KarpelesLab/cryptutil v0.2.30
	github.com/KarpelesLab/emitter v0.2.1
	github.com/KarpelesLab/goupd v0.4.5
	github.com/KarpelesLab/jwt v0.1.11
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/ringbuf v0.1.2
	github.com/KarpelesLab/spotlib v0.2.14
	github.com/KarpelesLab/spotproto v0.2.0
	github.com/KarpelesLab/tpmlib v0.1.6
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/google/go-tpm v0.9.1
	github.com/google/go-tpm-tools v0.4.4
	github.com/google/uuid v1.6.0
	github.com/quic-go/quic-go v0.47.0
	go.etcd.io/bbolt v1.3.11
	golang.org/x/crypto v0.27.0
)

require (
	github.com/KarpelesLab/pjson v0.1.9 // indirect
	github.com/KarpelesLab/rest v0.5.23 // indirect
	github.com/KarpelesLab/typutil v0.2.26 // indirect
	github.com/KarpelesLab/webutil v0.2.2 // indirect
	github.com/ModChain/edwards25519 v1.0.0 // indirect
	github.com/coder/websocket v1.8.12 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-configfs-tsm v0.3.2 // indirect
	github.com/google/go-sev-guest v0.11.1 // indirect
	github.com/google/go-tdx-guest v0.3.1 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/google/pprof v0.0.0-20241001023024-f4c0cfd0cf1d // indirect
	github.com/onsi/ginkgo/v2 v2.20.2 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.4.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/exp v0.0.0-20240909161429-701f63a606c0 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.29.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
	golang.org/x/tools v0.25.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
)

retract (
	v0.9.8 // crash on rpc
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
