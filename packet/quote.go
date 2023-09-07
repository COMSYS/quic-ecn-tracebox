package packet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var ErrICMPTrunc = errors.New("ICMP layer truncated to less than 8 bytes")
var ErrNotICMPQuote = errors.New("not a time exceeded ICMP message")

// layers.{ICMP,ICMPv6} are inconsistent w.r.t. the handling of the "unused" bytes
// in Time Exceeded messages. Since we only use the Type field from the ICMP header,
// it's easiest to just skip gopacket's ICMP code entirely.
func parseICMPTimeExc(typ uint8, data []byte, df gopacket.DecodeFeedback) ([]byte, error) {
	const icmpHeaderSize = 8
	if len(data) < icmpHeaderSize {
		df.SetTruncated()
		return nil, ErrICMPTrunc
	}
	if data[0] == typ {
		return data[icmpHeaderSize:], nil
	}
	return nil, ErrNotICMPQuote
}

type ICMPQuote struct {
	buf       []byte
	timestamp time.Time
	srcIP     net.IP
	quoteData []byte
	quoteFlow IPFlow
	tos       uint8
	quoteTOS  uint8
	quoteTTL  uint8
	trunc     bool
}

var _ Quote = &ICMPQuote{}

func NewICMPQuote(snaplen int) *ICMPQuote {
	return &ICMPQuote{buf: make([]byte, 0, snaplen)}
}

func (p *ICMPQuote) Truncated() bool {
	return p.trunc
}

func (p *ICMPQuote) SetTruncated() {
	p.trunc = true
}

func (p *ICMPQuote) CopyDecode(data []byte, ci gopacket.CaptureInfo) error {
	// Take ownership of packet data to support zero-copy capture
	n := copy(p.buf[:cap(p.buf)], data)
	p.buf = p.buf[:n]

	// Reset to default state
	p.trunc = false
	p.timestamp = ci.Timestamp

	var eth layers.Ethernet
	if err := eth.DecodeFromBytes(p.buf, p); err != nil {
		return err
	}

	switch eth.NextLayerType() {
	case layers.LayerTypeIPv4:
		return p.decodeIPv4()
	case layers.LayerTypeIPv6:
		return p.decodeIPv6()
	}
	return ErrNotICMPQuote
}

func (p *ICMPQuote) decodeIPv4() error {
	var ip layers.IPv4
	if err := ip.DecodeFromBytes(p.buf[ethSize:], p); err != nil {
		return err
	}
	p.tos = ip.TOS
	p.srcIP = ip.SrcIP

	if ip.NextLayerType() != layers.LayerTypeICMPv4 {
		return ErrNotICMPQuote
	}
	payload, err := parseICMPTimeExc(layers.ICMPv4TypeTimeExceeded, ip.Payload, p)
	if err != nil {
		return err
	}

	// Reuse ip layer for quote payload
	if err := ip.DecodeFromBytes(payload, p); err != nil {
		return err
	}
	p.quoteTOS = ip.TOS
	p.quoteTTL = ip.TTL
	p.quoteData = ip.Payload
	if len(ip.Payload) < 4 {
		return ErrQuoteTrunc
	}

	srcPort := binary.BigEndian.Uint16(ip.Payload)
	dstPort := binary.BigEndian.Uint16(ip.Payload[2:])
	p.quoteFlow, _ = NewIPFlow(ip.SrcIP, ip.DstIP, srcPort, dstPort, ip.Protocol)
	return nil
}

func (p *ICMPQuote) decodeIPv6() error {
	var ip layers.IPv6
	if err := ip.DecodeFromBytes(p.buf[ethSize:], p); err != nil {
		return err
	}
	p.tos = ip.TrafficClass
	p.srcIP = ip.SrcIP

	if ip.NextLayerType() != layers.LayerTypeICMPv6 {
		return ErrNotICMPQuote
	}
	payload, err := parseICMPTimeExc(layers.ICMPv6TypeTimeExceeded, ip.Payload, p)
	if err != nil {
		return err
	}

	// Reuse ip layer for quote payload
	if err := ip.DecodeFromBytes(payload, p); err != nil {
		return err
	}
	p.quoteTOS = ip.TrafficClass
	p.quoteTTL = ip.HopLimit
	p.quoteData = ip.Payload
	if len(ip.Payload) < 4 {
		return ErrQuoteTrunc
	}

	srcPort := binary.BigEndian.Uint16(ip.Payload)
	dstPort := binary.BigEndian.Uint16(ip.Payload[2:])
	p.quoteFlow, _ = NewIPFlow(ip.SrcIP, ip.DstIP, srcPort, dstPort, ip.NextHeader)
	return nil
}

func (lhs *ICMPQuote) Equal(q Quote) bool {
	rhs, _ := q.(*ICMPQuote)
	return rhs != nil && bytes.Equal(lhs.buf[ethSize:], rhs.buf[ethSize:])
}

func (p *ICMPQuote) TOS() uint8 {
	return p.tos
}

func (p *ICMPQuote) Source() net.IP {
	return p.srcIP
}

func (p *ICMPQuote) Timestamp() time.Time {
	return p.timestamp
}

func (p *ICMPQuote) QuoteTOS() uint8 {
	return p.quoteTOS
}

func (p *ICMPQuote) QuoteTTL() uint8 {
	return p.quoteTTL
}

func (p *ICMPQuote) QuoteData() []byte {
	return p.quoteData
}

func (p *ICMPQuote) QuoteFlow() IPFlow {
	return p.quoteFlow
}
