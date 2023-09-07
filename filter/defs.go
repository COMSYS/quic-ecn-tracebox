package filter

import (
	"net/netip"
)

// IPFilter consumers define the meaning of the bits
type MeasurementSet uint8

func (s MeasurementSet) IsEmpty() bool {
	return s == 0
}

func (super MeasurementSet) Contains(sub MeasurementSet) bool {
	return (super & sub) == sub
}

func (s MeasurementSet) Union(add MeasurementSet) MeasurementSet {
	return s | add
}

func (s MeasurementSet) Difference(remove MeasurementSet) MeasurementSet {
	return s &^ remove
}

type IPFilter interface {
	// Whether IP should be filtered (true) or retained (false),
	// considering the types of measurements to perform.
	DoFilter(ip netip.Addr, measurements MeasurementSet) bool
	// Mark IP as seen for the given types of measurements
	Merge(ip netip.Addr, measurements MeasurementSet)
	// Reset the filter to its initial state
	Reset()
}

type PeekableIPFilter interface {
	IPFilter
	// Like DoFilter(), but without changing the filter's state
	Peek(ip netip.Addr, measurements MeasurementSet) bool
}

type ipType uint8

const (
	ipNil ipType = 0
	ipv4         = iota
	ipv6
)

func getIPType(ip netip.Addr) ipType {
	if ip.Is4() || ip.Is4In6() {
		return ipv4
	} else if ip.IsValid() {
		return ipv6
	}
	return ipNil
}
