//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type MissingAddrError struct {
	ifName string
	in6    bool
}

var _ error = MissingAddrError{}

func (e MissingAddrError) Error() string {
	if e.in6 {
		return fmt.Sprintf("interface %q does not have a global unicast IPv6 address", e.ifName)
	}
	return fmt.Sprintf("interface %q does not have a global unicast IPv4 address", e.ifName)
}

type IPConn net.IPConn

var ipLevel = [2]int{
	syscall.IPPROTO_IP,
	syscall.IPPROTO_IPV6,
}

var pmtudOpt = [2]int{
	syscall.IP_MTU_DISCOVER,
	syscall.IPV6_MTU_DISCOVER,
}

var pmtudVal = [2]int{
	syscall.IP_PMTUDISC_PROBE,
	syscall.IPV6_PMTUDISC_PROBE,
}

func NewIPConn(network string, ifName string) (*IPConn, error) {
	in6 := strings.HasPrefix(network, "ip6:")
	addr, err := getIPAddr(ifName, in6)
	if err != nil {
		return nil, err
	}

	ipidx := 0
	if in6 {
		ipidx = 1
	}
	sl := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) (err error) {
		err2 := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
			if err != nil {
				return
			}
			err = syscall.SetsockoptInt(int(fd), ipLevel[ipidx], pmtudOpt[ipidx], pmtudVal[ipidx])
		})
		if err == nil {
			err = err2
		}
		return
	}}

	pc, err := sl.ListenPacket(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}

	if in6 {
		ip6c := ipv6.NewPacketConn(pc)
		err = ip6c.SetBPF(bpfIgnoreAll)
	} else {
		ip4c := ipv4.NewPacketConn(pc)
		err = ip4c.SetBPF(bpfIgnoreAll)
	}
	if err != nil {
		return nil, err
	}

	c := pc.(*net.IPConn)
	return (*IPConn)(c), nil
}

func getIPAddr(ifName string, in6 bool) (net.IP, error) {
	i, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := i.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || (ipnet.IP.To4() == nil) != in6 {
			// To4() == nil is true for IPv6 and false for IPv4
			continue
		}
		if ipnet.IP.IsGlobalUnicast() {
			return ipnet.IP, nil
		}
	}
	return nil, MissingAddrError{ifName: ifName, in6: in6}
}

func (c *IPConn) LocalAddr() *net.IPAddr {
	ic := (*net.IPConn)(c)
	return ic.LocalAddr().(*net.IPAddr)
}

func (c *IPConn) WriteMsgIP(b, oob []byte, addr net.IPAddr) (int, int, error) {
	ic := (*net.IPConn)(c)
	return ic.WriteMsgIP(b, oob, &addr)
}
