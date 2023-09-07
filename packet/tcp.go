package packet

import (
	"encoding/binary"

	"github.com/die-net/fastrand"
)

const tcpFlagOff = 13
const (
	TCPFlagFIN uint8 = 1 << iota
	TCPFlagSYN
	TCPFlagRST
	TCPFlagPSH
	TCPFlagACK
	TCPFlagURG
	TCPFlagECE
	TCPFlagCWR
)

var tcpSYNECN = [20]byte{
	0, 0, 0, 0, // src port, dst port (set by sender)
	0, 0, 0, 0, // sequence number (set by sender)
	0, 0, 0, 0, // ACK number (not used)
	(5 << 4),                             // data offset, reserved bits
	TCPFlagSYN | TCPFlagECE | TCPFlagCWR, // ECN-setup SYN flags
	0x20, 00,                             // window size (8KB)
	0, 0, 0, 0, // checksum (set by sender), urgent pointer (not used)
}

type TCPSYNPacket struct {
	IPSockCtl
	data [20]byte
}

var _ Packet = &TCPSYNPacket{}
var _ TCPPacket = &TCPSYNPacket{}

func NewTCPSYNPacket(ipv6 bool) *TCPSYNPacket {
	return &TCPSYNPacket{data: tcpSYNECN, IPSockCtl: NewIPSockCtl(ipv6)}
}

func (p *TCPSYNPacket) Data() []byte {
	return p.data[:]
}

func (p *TCPSYNPacket) TCPFlags() uint8 {
	return p.data[tcpFlagOff]
}

func (p *TCPSYNPacket) GetOOB() []byte {
	return p.IPSockCtl
}

func (p *TCPSYNPacket) PrepareForTrace(flow IPFlow) {
	var csum inetChecksum
	csum.pseudoheader(&flow, len(p.data))

	p.data[17] = 0
	p.data[16] = 0
	binary.BigEndian.PutUint16(p.data[:], flow.SrcPort)
	binary.BigEndian.PutUint16(p.data[2:], flow.DstPort)

	// Randomize the ISN as is good practice for TCP stacks.
	// Byte order is meaningless for a random number,
	// so we save some work by using x86's host byte order.
	isn := fastrand.Uint32()
	binary.LittleEndian.PutUint32(p.data[4:], isn)

	csum.add(p.data[:])
	binary.BigEndian.PutUint16(p.data[16:], csum.finalize())
}
