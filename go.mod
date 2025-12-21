module github.com/KarpelesLab/fleet

go 1.24.0

require (
	github.com/BottleFmt/gobottle v1.0.0
	github.com/KarpelesLab/cloudinfo v0.1.7
	github.com/KarpelesLab/emitter v0.3.0
	github.com/KarpelesLab/goupd v0.4.7
	github.com/KarpelesLab/jwt v0.1.11
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/spotlib v0.3.0
	github.com/KarpelesLab/spotproto v0.3.0
	github.com/KarpelesLab/tpmlib v0.1.8
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/google/uuid v1.6.0
	github.com/quic-go/quic-go v0.57.1
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.46.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/KarpelesLab/mldsa v0.1.1 // indirect
	github.com/KarpelesLab/pjson v0.2.0 // indirect
	github.com/KarpelesLab/rest v0.6.15 // indirect
	github.com/KarpelesLab/shutdown v1.1.1 // indirect
	github.com/KarpelesLab/slhdsa v0.1.0 // indirect
	github.com/KarpelesLab/typutil v0.2.33 // indirect
	github.com/KarpelesLab/webutil v0.2.6 // indirect
	github.com/ModChain/edwards25519 v1.1.5 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/google/go-configfs-tsm v0.3.3 // indirect
	github.com/google/go-sev-guest v0.14.1 // indirect
	github.com/google/go-tdx-guest v0.3.2-0.20241009005452-097ee70d0843 // indirect
	github.com/google/go-tpm v0.9.7 // indirect
	github.com/google/go-tpm-tools v0.4.7 // indirect
	github.com/google/logger v1.1.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/mock v0.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

retract (
	v0.9.8 // crash on rpc
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
