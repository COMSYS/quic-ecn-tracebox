//go:build linux
// +build linux

package main

import (
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const ethSize = 14
const ip6Size = 40
const ipMaxSize = 4 * 0xf             // bounded by IPv4's IHL (IPv6 is smaller)
const icmpCapLen = 8 + ipMaxSize + 64 // IP header + up to 64 bytes of payload
const totalIpCapLen = ethSize + ipMaxSize + icmpCapLen

const capLenAlign = 16 // for efficient SSE-based memcpy
const alignedIpCapLen = (totalIpCapLen + capLenAlign - 1) &^ (capLenAlign - 1)

var bpfIgnoreAll = []bpf.RawInstruction{
	bpf.RawInstruction{Op: unix.BPF_RET | unix.BPF_K, K: 0},
}

func calcSkip(src, dst uint8) uint8 {
	if dst <= src {
		panic("calcSkip: dst before src")
	}
	return dst - src - 1
}

// Generated by: tcpdump -i eth0 -d 'inbound and (icmp[icmptype] = icmp-timxceed or icmp6[icmp6type] = icmp6-timeexceeded)'
var bpfOnlyICMPQuote = []bpf.Instruction{
	/* 00 */ bpf.LoadExtension{Num: bpf.ExtType}, // skb->pkt_type (Linux only)
	/* 01 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING, SkipTrue: calcSkip(1, 17)},
	/* 02 */ bpf.LoadAbsolute{Off: 12, Size: 2}, // EtherType
	/* 03 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.ETH_P_IP, SkipFalse: calcSkip(3, 11)},
	/* 04 */ bpf.LoadAbsolute{Off: ethSize + 9, Size: 1}, // Protocol
	/* 05 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_ICMP, SkipFalse: calcSkip(5, 17)},
	/* 06 */ bpf.LoadAbsolute{Off: ethSize + 6, Size: 2}, // Flags, Fragment Offset
	/* 07 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: calcSkip(7, 17)},
	/* 08 */ bpf.LoadMemShift{Off: ethSize}, // 4*IHL
	/* 09 */ bpf.LoadIndirect{Off: ethSize, Size: 1}, // ICMP Type [4*IHL + ethSize]
	/* 10 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: layers.ICMPv4TypeTimeExceeded,
		SkipTrue: calcSkip(10, 16), SkipFalse: calcSkip(10, 17)},

	// A is EtherType here (branch from #03)
	/* 11 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.ETH_P_IPV6, SkipFalse: calcSkip(11, 17)},
	/* 12 */ bpf.LoadAbsolute{Off: ethSize + 6, Size: 1}, // Next Header
	/* 13 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.IPPROTO_ICMPV6, SkipFalse: calcSkip(13, 17)},
	/* 14 */ bpf.LoadAbsolute{Off: ethSize + ip6Size, Size: 1}, // ICMP Type
	/* 15 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: layers.ICMPv6TypeTimeExceeded, SkipFalse: calcSkip(15, 17)},

	/* 16 */ bpf.RetConstant{Val: alignedIpCapLen},
	/* 17 */ bpf.RetConstant{Val: 0},
}