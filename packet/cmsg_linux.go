//go:build linux
// +build linux

package packet

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

type IPSockCtl []byte

var cmsgLevel = [2]int32{
	unix.IPPROTO_IP,
	unix.IPPROTO_IPV6,
}
var ttlType = [2]int32{
	unix.IP_TTL,
	unix.IPV6_HOPLIMIT,
}
var tosType = [2]int32{
	unix.IP_TOS,
	unix.IPV6_TCLASS,
}

var cmsgIntLen = unix.CmsgLen(unix.SizeofInt)
var cmsgIntSize = unix.CmsgSpace(unix.SizeofInt)
var cmsgDataOff = unix.CmsgLen(0)

func NewIPSockCtl(ipv6 bool) IPSockCtl {
	ipidx := 0
	if ipv6 {
		ipidx = 1
	}

	oob := make([]byte, 2*cmsgIntSize)
	cmsgMarshalInt(oob, cmsgLevel[ipidx], ttlType[ipidx], defaultTTL)
	cmsgMarshalInt(oob[cmsgIntSize:], cmsgLevel[ipidx], tosType[ipidx], defaultTOS)
	return oob
}

func cmsgMarshalInt(cmsg []byte, level, typ int32, val uint8) {
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&cmsg[0]))
	hdr.SetLen(cmsgIntLen)
	hdr.Level = level
	hdr.Type = typ
	cmsg[cmsgDataOff] = val // little endian, other bytes are 0
}

func (cm IPSockCtl) TTL() uint8 {
	return cm[cmsgDataOff]
}
func (cm IPSockCtl) SetTTL(ttl uint8) {
	cm[cmsgDataOff] = ttl
}

func (cm IPSockCtl) TOS() uint8 {
	return cm[cmsgIntSize+cmsgDataOff]
}
func (cm IPSockCtl) SetTOS(tos uint8) {
	cm[cmsgIntSize+cmsgDataOff] = tos
}
