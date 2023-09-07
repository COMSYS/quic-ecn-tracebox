package filter

import (
	"net"
	"net/netip"
)

type fixedIPv4 [net.IPv4len]byte
type fixedIPv6 [net.IPv6len]byte

// Map memory usage can be estimated as follows:
//  1. Let B = ceil(log2(sizehint / 6.5)). This is the number of allocated buckets.
//  2. Byte size of the buckets is (amd64): 2^B * (8 * (1 + KEY_SIZE + VALUE_SIZE) + 8).
//     The map structure itself adds some small constant overhead.
type UniqueIPFilter struct {
	ip4seen map[fixedIPv4]MeasurementSet
	ip6seen map[fixedIPv6]MeasurementSet
}

var _ PeekableIPFilter = &UniqueIPFilter{}

func NewUniqueIPFilter(initialIPv4, initialIPv6 int) *UniqueIPFilter {
	return &UniqueIPFilter{
		ip4seen: make(map[fixedIPv4]MeasurementSet, initialIPv4),
		ip6seen: make(map[fixedIPv6]MeasurementSet, initialIPv6),
	}
}

func (f *UniqueIPFilter) DoFilter(ip netip.Addr, inp MeasurementSet) bool {
	if f.Peek(ip, inp) {
		return true
	}
	f.Merge(ip, inp)
	return false
}

func (f *UniqueIPFilter) Peek(ip netip.Addr, inp MeasurementSet) bool {
	var cur MeasurementSet
	var seen bool
	switch getIPType(ip) {
	case ipv4:
		cur, seen = f.ip4seen[ip.As4()]
	case ipv6:
		cur, seen = f.ip6seen[ip.As16()]
	default:
		return true
	}
	return seen && cur.Contains(inp)
}

func (f *UniqueIPFilter) Merge(ip netip.Addr, inp MeasurementSet) {
	switch getIPType(ip) {
	case ipv4:
		ip4 := ip.As4()
		cur := f.ip4seen[ip4]
		f.ip4seen[ip4] = cur.Union(inp)
	case ipv6:
		ip6 := ip.As16()
		cur := f.ip6seen[ip6]
		f.ip6seen[ip6] = cur.Union(inp)
	}
}

func (f *UniqueIPFilter) Reset() {
	// gc optimizes these loops to an internal mapclear() call
	m1 := f.ip4seen
	for k := range m1 {
		delete(m1, k)
	}
	m2 := f.ip6seen
	for k := range m2 {
		delete(m2, k)
	}
}
