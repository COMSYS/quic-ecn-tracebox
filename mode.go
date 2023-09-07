package main

import (
	"encoding"

	"github.com/COMSYS/quic-ecn-tracebox/packet"
	"github.com/google/gopacket/layers"
)

type TraceboxMode uint8

const (
	TraceboxInvalidMode TraceboxMode = 0
	TraceboxQUIC        TraceboxMode = iota
	TraceboxTCP
)

var _ encoding.TextMarshaler = TraceboxMode(0)

func (m TraceboxMode) String() string {
	switch m {
	case TraceboxInvalidMode:
		return "invalid"
	case TraceboxQUIC:
		return "quic"
	case TraceboxTCP:
		return "tcp"
	}
	return "undefined"
}

func (m TraceboxMode) MarshalText() ([]byte, error) {
	return []byte(m.String()), nil
}

func (m TraceboxMode) IPProtocol() layers.IPProtocol {
	switch m {
	case TraceboxQUIC:
		return layers.IPProtocolUDP
	case TraceboxTCP:
		return layers.IPProtocolTCP
	}
	panic("invalid TraceboxMode in IPProtocol()")
}

func (m TraceboxMode) DstPortDefault() uint16 {
	switch m {
	case TraceboxQUIC:
		return 443
	case TraceboxTCP:
		return 443
	}
	panic("invalid TraceboxMode in DefaultDstPort()")
}

func (m TraceboxMode) NewPktFunc(ipv6 bool) func() interface{} {
	switch m {
	case TraceboxQUIC:
		return func() interface{} {
			return packet.NewQUICPacket(ipv6)
		}
	case TraceboxTCP:
		return func() interface{} {
			return packet.NewTCPSYNPacket(ipv6)
		}
	}
	panic("invalid TraceboxMode in NewPktFunc()")
}
