module github.com/KarpelesLab/fleet

go 1.19

require (
	github.com/KarpelesLab/goupd v0.3.1
	github.com/KarpelesLab/jwt v0.1.2
	github.com/KarpelesLab/rchan v1.0.1
	github.com/KarpelesLab/ringbuf v0.1.2
	github.com/google/uuid v1.3.0
	go.etcd.io/bbolt v1.3.7
	golang.org/x/crypto v0.10.0
)

require golang.org/x/sys v0.9.0 // indirect

retract (
	[v0.9.1, v0.9.7] // bug with ssh RPC
	v0.9.0 // buggy, not to be used
	[v0.8.8, v0.8.10] // experimental fssh support failure
)
