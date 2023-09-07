package packet

import (
	"bytes"
	"encoding"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

type valueIP [net.IPv6len]byte

const prefix46len = net.IPv6len - net.IPv4len

var prefix46 = [prefix46len]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
var _ encoding.TextMarshaler = valueIP{}

func (ip *valueIP) CopyFrom(nip net.IP) bool {
	switch len(nip) {
	case net.IPv4len:
		copy(ip[:], prefix46[:])
		copy(ip[prefix46len:], nip)
		return true
	case net.IPv6len:
		copy(ip[:], nip)
		return true
	}
	return false
}

func (ip *valueIP) ToCanonical() []byte {
	if bytes.Equal(ip[:prefix46len], prefix46[:]) {
		return ip[prefix46len:]
	}
	return ip[:]
}

func (ip valueIP) MarshalText() ([]byte, error) {
	return net.IP(ip[:]).MarshalText()
}

type IPFlow struct {
	SrcIP   valueIP           `json:"saddr"`
	DstIP   valueIP           `json:"daddr"`
	SrcPort uint16            `json:"sport"`
	DstPort uint16            `json:"dport"`
	Proto   layers.IPProtocol `json:"proto"`
}

func NewIPFlow(
	srcIP net.IP, dstIP net.IP,
	srcPort uint16, dstPort uint16,
	proto layers.IPProtocol,
) (IPFlow, bool) {
	f := IPFlow{SrcPort: srcPort, DstPort: dstPort, Proto: proto}
	if !f.SrcIP.CopyFrom(srcIP) || !f.DstIP.CopyFrom(dstIP) {
		return IPFlow{}, false
	}
	return f, true
}

func (f IPFlow) String() string {
	src := net.IP(f.SrcIP[:])
	dst := net.IP(f.DstIP[:])
	return fmt.Sprintf("%s:%d -[%s]-> %s:%d", src, f.SrcPort, f.Proto, dst, f.DstPort)
}
