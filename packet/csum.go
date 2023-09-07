package packet

// ADAPTED FROM gopacket/layers/tcpip.go
// RFC 1071 Internet Checksum
type inetChecksum struct {
	sum uint32
}

// Precompute a partial checksum for static payloads
func prepareChecksum(data []byte) (c inetChecksum) {
	c.add(data)
	return
}

func (c *inetChecksum) pseudoheader(flow *IPFlow, totalLen int) {
	length := uint32(totalLen)
	c.sum += uint32(flow.Proto) // zero + protocol/Next Header
	c.sum += length & 0xffff
	c.sum += length >> 16
	c.add(flow.SrcIP.ToCanonical())
	c.add(flow.DstIP.ToCanonical())
}

func (c *inetChecksum) add(data []byte) {
	if len(data)%2 != 0 {
		panic("must write an even number of bytes!")
	}
	for i := 0; i < len(data)-1; i += 2 {
		c.sum += uint32(data[i]) << 8
		c.sum += uint32(data[i+1])
	}
}

func (c inetChecksum) finalize() uint16 {
	for c.sum > 0xffff {
		c.sum = (c.sum >> 16) + (c.sum & 0xffff)
	}
	return ^uint16(c.sum)
}
