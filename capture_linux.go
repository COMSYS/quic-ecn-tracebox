//go:build linux
// +build linux

package main

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"

	"github.com/COMSYS/quic-ecn-tracebox/packet"
	"github.com/google/gopacket/afpacket"
	"golang.org/x/net/bpf"
)

const capTotalBufSize = 2 * 1024 * 1024 // libpcap default
const capPollTimeout = afpacket.OptPollTimeout(100 * time.Millisecond)

var capBlockSize = afpacket.OptBlockSize(128 * 2048)
var capNumBlocks afpacket.OptNumBlocks

func init() {
	// Round capBlockSize up to a multiple of the page size
	align := syscall.Getpagesize() - 1
	size := (int(capBlockSize) + align) &^ align
	capBlockSize = afpacket.OptBlockSize(size)
	capNumBlocks = afpacket.OptNumBlocks((capTotalBufSize + capBlockSize - 1) / capBlockSize)
}

type QuotePool interface {
	PutQuote(q packet.Quote)
}

type mgmtOpType uint8

const (
	mgmtOpInvalid mgmtOpType = 0 // (invalid) default value
	mgmtAddFlow   mgmtOpType = iota
	mgmtDeleteFlow
	mgmtStopMultiplexer
)

type mgmtOp struct {
	dest chan<- packet.Quote
	flow packet.IPFlow
	typ  mgmtOpType
}

type CapMultiplexer struct {
	packetSource *afpacket.TPacket
	quotePool    *sync.Pool
	flows        map[packet.IPFlow]chan<- packet.Quote
	mgmt         chan mgmtOp
	done         chan struct{}
}

var _ QuotePool = &CapMultiplexer{}

func NewCapMultiplexer(ifName string, numTracers uint) (*CapMultiplexer, error) {
	filter, err := bpf.Assemble(bpfOnlyICMPQuote)
	if err != nil {
		return nil, err
	}

	p, err := afpacket.NewTPacket(
		afpacket.SocketRaw, afpacket.TPacketVersion3,
		capBlockSize, capNumBlocks, afpacket.OptFrameSize(capBlockSize),
		afpacket.OptInterface(ifName), capPollTimeout,
	)
	if err != nil {
		return nil, err
	}
	if err = p.SetBPF(filter); err != nil {
		return nil, err
	}

	return &CapMultiplexer{
		packetSource: p,
		quotePool: &sync.Pool{New: func() interface{} {
			return packet.NewICMPQuote(alignedIpCapLen)
		}},
		flows: make(map[packet.IPFlow]chan<- packet.Quote, numTracers),
		mgmt:  make(chan mgmtOp, numTracers),
		done:  make(chan struct{}),
	}, nil
}

func (m *CapMultiplexer) getQuote() *packet.ICMPQuote {
	return m.quotePool.Get().(*packet.ICMPQuote)
}

func (m *CapMultiplexer) PutQuote(q packet.Quote) {
	if _, ok := q.(*packet.ICMPQuote); !ok {
		log.Printf("returning quote failed: incorrect type %T", q)
		return
	}
	m.quotePool.Put(q)
}

func (m *CapMultiplexer) AddFlow(f packet.IPFlow, c chan<- packet.Quote) {
	m.mgmt <- mgmtOp{typ: mgmtAddFlow, flow: f, dest: c}
}

func (m *CapMultiplexer) DeleteFlow(f packet.IPFlow) {
	m.mgmt <- mgmtOp{typ: mgmtDeleteFlow, flow: f}
}

func (m *CapMultiplexer) Stop() {
	m.mgmt <- mgmtOp{typ: mgmtStopMultiplexer}
	<-m.done
}

func (m *CapMultiplexer) Run() {
	defer close(m.done)
	var panicMsg string
	var chanDrops, unkFlowDrops uint
	q := m.getQuote()

	for {
		// Process mgmt operations before the packet
		data, ci, err := m.packetSource.ZeroCopyReadPacketData()
		if m.processMgmt() {
			// Received a request to stop
			break
		}
		if err == afpacket.ErrTimeout {
			continue
		}
		if err != nil {
			// Assume polling errors are not recoverable
			panicMsg = fmt.Sprintf("reading packet failed: %v", err)
			log.Print(panicMsg)
			break
		}

		if err = q.CopyDecode(data, ci); err != nil {
			if err != packet.ErrNotICMPQuote {
				log.Printf("decoding packet failed: %v", err)
			}
			continue
		}

		f := q.QuoteFlow()
		if c, ok := m.flows[f]; ok {
			select {
			case c <- q:
				q = m.getQuote()
			default:
				chanDrops++
			}
		} else {
			unkFlowDrops++
		}
	}
	m.PutQuote(q)

	if _, stats, err := m.packetSource.SocketStats(); err != nil {
		log.Printf("retrieving capture stats failed: %v", err)
	} else {
		log.Printf(
			"capture stats:\n\t%10d packets\n\t%10d drops (kernel)\n\t%10d drops (chan)\n\t%10d drops (unk flow)\n\t%10d queue freezes",
			stats.Packets(), stats.Drops(), chanDrops, unkFlowDrops, stats.QueueFreezes(),
		)
	}

	m.packetSource.Close()
	if panicMsg != "" {
		panic(panicMsg)
	}
}

func (m *CapMultiplexer) processMgmt() (stop bool) {
	for {
		var op mgmtOp
		select {
		case op = <-m.mgmt:
			// see below
		default:
			return // done
		}

		switch op.typ {
		case mgmtAddFlow:
			m.flows[op.flow] = op.dest
		case mgmtDeleteFlow:
			delete(m.flows, op.flow)
		case mgmtStopMultiplexer:
			stop = true
		}
	}
}
