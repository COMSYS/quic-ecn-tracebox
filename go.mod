module github.com/COMSYS/quic-ecn-tracebox

go 1.18

require (
	// We rely on internal details of jsonparser. Take care when upgrading!
	github.com/buger/jsonparser v1.1.1
	github.com/die-net/fastrand v0.0.0-20220628163435-fce45c455ef1
	github.com/google/gopacket v1.1.19
	go.uber.org/ratelimit v0.2.1-0.20221031031303-a12885fa6127
	golang.org/x/net v0.8.0
	golang.org/x/sys v0.6.0
)

require github.com/benbjohnson/clock v1.3.0 // indirect
