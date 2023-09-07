package packet

import (
	"encoding/hex"
	"math/bits"
	"net"
	"time"
)

const tosECNMask uint8 = 0b11
const tosDSCPMask uint8 = ^tosECNMask

type byteDiff struct {
	Sent, Returned byte
}

func diffByte(sent, returned byte) *byteDiff {
	if sent != returned {
		return &byteDiff{sent, returned}
	}
	return nil
}

func diffTCPFlags(sent Packet, returned Quote) *byteDiff {
	p, ok := sent.(TCPPacket)
	if !ok {
		return nil
	}
	data := returned.QuoteData()
	if tcpFlagOff >= len(data) {
		return nil
	}
	return diffByte(p.TCPFlags(), data[tcpFlagOff])
}

type dataDiff struct {
	// Index of first diverging bit (MSB first, like protocol headers)
	DiffStart uint
	// Up to 32 bytes of data, hex-encoded
	Sent, Returned string
}

func diffData(sent, returned []byte) *dataDiff {
	diff := -1
	size := len(returned)
	if size > len(sent) {
		// If data was extended in the network, there is a diff just beyond the sent data
		size = len(sent)
		diff = 8 * size
	}

	for idx := 0; idx < size; idx++ {
		s := sent[idx]
		r := returned[idx]
		if s != r {
			diff = 8 * idx
			// s ^ r has a 1 at every diverging bit, we need the offset of the first such bit
			diff += bits.LeadingZeros8(s ^ r)
			break
		}
	}

	if diff >= 0 {
		sentHex := leading32Hex(sent)
		retHex := sentHex // can reuse sent if diff is beyond 32nd byte
		if diff < 32*8 {
			retHex = leading32Hex(returned)
		}
		return &dataDiff{DiffStart: uint(diff), Sent: sentHex, Returned: retHex}
	}
	return nil
}

func leading32Hex(data []byte) string {
	n := len(data)
	if n > 32 {
		n = 32
	}
	return hex.EncodeToString(data[:n])
}

type QuoteDiff struct {
	HopIP     net.IP    `json:"ip"`
	HopPTR    []string  `json:"ptr"`
	ReceiveMs uint32    `json:"receive_ms"`
	HopTOS    uint8     `json:"tos,omitempty"`
	TTL       uint8     `json:"qttl,omitempty"` // either 0 or >=2
	ECN       *byteDiff `json:"qecn,omitempty"`
	DSCP      *byteDiff `json:"qdscp,omitempty"`
	TCPFlags  *byteDiff `json:"qtcp,omitempty"`
	Data      *dataDiff `json:"qdata,omitempty"`
	Length    int       `json:"qlength,omitempty"`
}

func Diff(start time.Time, sent Packet, returned Quote) *QuoteDiff {
	receiveOff := returned.Timestamp().Sub(start)
	if receiveOff < 0 {
		receiveOff = 0
	}
	ttl := returned.QuoteTTL()
	if ttl == 1 {
		// Only expose quote TTL > 1
		ttl = 0
	}
	sentTOS := sent.TOS()
	retTOS := returned.QuoteTOS()

	return &QuoteDiff{
		HopIP:     cloneIP(returned.Source()),
		ReceiveMs: uint32(receiveOff.Milliseconds()),
		HopTOS:    returned.TOS(),
		TTL:       ttl,
		ECN:       diffByte(sentTOS&tosECNMask, retTOS&tosECNMask),
		DSCP:      diffByte(sentTOS&tosDSCPMask, retTOS&tosDSCPMask),
		TCPFlags:  diffTCPFlags(sent, returned),
		Data:      diffData(sent.Data(), returned.QuoteData()),
		Length:    len(returned.QuoteData()),
	}
}

func cloneIP(ip net.IP) net.IP {
	if t := ip.To4(); t != nil {
		ip = t
	}
	r := make(net.IP, len(ip))
	copy(r, ip)
	return r
}
