package packet

import "encoding/binary"

type QUICPacket struct {
	data []byte
	IPSockCtl
}

var _ Packet = &QUICPacket{}
var quicV1csum = prepareChecksum(quicV1Initial)

// Does not set either port!
func NewQUICPacket(ipv6 bool) *QUICPacket {
	totalLen := 8 + len(quicV1Initial)
	data := make([]byte, totalLen)

	// Sender sets both ports
	binary.BigEndian.PutUint16(data[4:], uint16(totalLen))
	// Sender sets checksum
	copy(data[8:], quicV1Initial)

	return &QUICPacket{data: data, IPSockCtl: NewIPSockCtl(ipv6)}
}

func (p *QUICPacket) Data() []byte {
	return p.data
}

func (p *QUICPacket) GetOOB() []byte {
	return p.IPSockCtl
}

func (p *QUICPacket) PrepareForTrace(flow IPFlow) {
	csum := quicV1csum
	csum.pseudoheader(&flow, len(p.data))

	p.data[7] = 0 // early bounds check
	p.data[6] = 0
	binary.BigEndian.PutUint16(p.data, flow.SrcPort)
	binary.BigEndian.PutUint16(p.data[2:], flow.DstPort)

	csum.add(p.data[:8])
	binary.BigEndian.PutUint16(p.data[6:], csum.finalize())
}
