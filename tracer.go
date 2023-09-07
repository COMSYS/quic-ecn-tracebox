package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/COMSYS/quic-ecn-tracebox/packet"
	"go.uber.org/ratelimit"
)

type traceShared struct {
	conn    *IPConn
	pktPool *sync.Pool
}

func newTraceShared(network string, ifName string, newPkt func() interface{}) (traceShared, error) {
	c, err := NewIPConn(network, ifName)
	if err != nil {
		return traceShared{}, err
	}
	return traceShared{conn: c, pktPool: &sync.Pool{New: newPkt}}, nil
}

const traceHopTimeout time.Duration = 3 * time.Second
const traceMaxTimeouts = 5

type TracerCtx struct {
	pacer    ratelimit.Limiter
	mp       *CapMultiplexer
	ip4      map[TraceboxMode]traceShared
	ip6      map[TraceboxMode]traceShared
	resolver net.Resolver
	lastPort uint32
}

func NewTracerCtx(config *TraceboxConfig) (*TracerCtx, error) {
	const minTraceDur = traceMaxTimeouts * traceHopTimeout
	pacer := ratelimit.New(
		int(config.tracerCount), ratelimit.Per(minTraceDur),
		ratelimit.WithoutSlack, // strict pacing, no bursts
	)
	ctx := &TracerCtx{
		pacer:    pacer,
		ip4:      make(map[TraceboxMode]traceShared, 2),
		ip6:      make(map[TraceboxMode]traceShared, 2),
		resolver: net.Resolver{},
		lastPort: uint32(config.minSrcPort) - 1, // overflow is ok, gets reversed below
	}

	var err error
	if ctx.mp, err = NewCapMultiplexer(config.traceIf, config.tracerCount); err != nil {
		return nil, err
	}
	if err = ctx.initMode(config, TraceboxQUIC); err != nil {
		return nil, err
	}
	if err = ctx.initMode(config, TraceboxTCP); err != nil {
		return nil, err
	}
	return ctx, nil
}

func (ctx *TracerCtx) initMode(config *TraceboxConfig, mode TraceboxMode) (err error) {
	net := fmt.Sprintf("ip4:%d", mode.IPProtocol())
	ctx.ip4[mode], err = newTraceShared(net, config.traceIf, mode.NewPktFunc(false))
	if err != nil || ctx.ip6 == nil {
		return
	}

	net = fmt.Sprintf("ip6:%d", mode.IPProtocol())
	ctx.ip6[mode], err = newTraceShared(net, config.traceIf, mode.NewPktFunc(true))
	if _, ok := err.(MissingAddrError); ok {
		// nil err also causes type assertion to fail (ok == false)
		// Some deployments don't have IPv6 connectivity, don't fail in that case
		log.Printf("WARNING: %s. Disabling IPv6 tracing.", err)
		ctx.ip6 = nil
		err = nil
	}
	return
}

type Tracer struct {
	ctx     *TracerCtx
	wg      *sync.WaitGroup
	input   <-chan *TraceboxTarget
	output  chan<- []byte
	timeout time.Duration
	srcPort uint16
	maxTTL  uint8
	tos     uint8
}

func (ctx *TracerCtx) NewTracer(
	wg *sync.WaitGroup, config *TraceboxConfig,
	input <-chan *TraceboxTarget, output chan<- []byte,
) *Tracer {
	srcPort := atomic.AddUint32(&ctx.lastPort, 1)
	if srcPort > 0xffff {
		panic("out of source ports")
	}
	return &Tracer{
		ctx: ctx, wg: wg, input: input, output: output, timeout: config.traceTimeout,
		srcPort: uint16(srcPort), maxTTL: config.maxTTL, tos: config.traceTOS,
	}
}

func (t *Tracer) Run() {
	defer t.wg.Done()
	noIPv6 := t.ctx.ip6 == nil
	for tgt := range t.input {
		if noIPv6 && !tgt.IsIPv4() {
			continue
		}
		t.ctx.pacer.Take()

		var res []byte
		ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
		switch tgt.Mode {
		case TraceboxQUIC, TraceboxTCP:
			var err error
			trace := t.newPacketTrace(tgt)
			res, err = trace.doTrace(ctx)
			t.ctx.mp.DeleteFlow(trace.flow)
			trace.drainQuotes() // don't leak any quote structs
			if err != nil {
				log.Printf("encoding trace result failed: %v", err)
			}
		default:
			log.Printf("received unexpected tracebox mode %s (%#4x)", tgt.Mode, tgt.Mode)
		}

		cancel()
		if len(res) > 0 {
			t.output <- res
		}
	}
}

func (t *Tracer) newPacketTrace(tgt *TraceboxTarget) PacketTrace {
	mode := tgt.Mode
	var ts traceShared
	if tgt.IsIPv4() {
		ts = t.ctx.ip4[mode]
	} else {
		// ip6 != nil is checked in (*Tracer).Run()
		ts = t.ctx.ip6[mode]
	}
	dstPort := tgt.DstPort
	if dstPort == 0 {
		dstPort = mode.DstPortDefault()
	}

	// can't fail: both src and dst IP are verified IPs
	f, _ := packet.NewIPFlow(ts.conn.LocalAddr().IP, tgt.DstIP, t.srcPort, dstPort, mode.IPProtocol())
	c := make(chan packet.Quote, 5)
	t.ctx.mp.AddFlow(f, c)

	return PacketTrace{
		mp: t.ctx.mp, traceShared: ts, resolver: &t.ctx.resolver,
		target: tgt, quotes: c, flow: f, maxTTL: t.maxTTL, tos: t.tos,
	}
}

type PacketTrace struct {
	mp QuotePool
	traceShared
	resolver *net.Resolver
	target   *TraceboxTarget
	quotes   <-chan packet.Quote
	flow     packet.IPFlow
	maxTTL   uint8
	tos      uint8
}

func (t *PacketTrace) doTrace(ctx context.Context) ([]byte, error) {
	start := time.Now()
	qdelay := queueingDelay(start, t.target)
	r := TraceResult{
		TraceTool: comsysTool, TraceVP: comsysVP, ScanDate: t.target.ScanDate, ScanSource: t.target.ScanSource,
		BuildID: buildid, Mode: t.target.Mode, Status: statusSuccess, Trigger: t.target.Trigger,
		URL: t.target.URL, Flow: t.flow, Timestamp: start.UTC(), DelayMs: uint32(qdelay.Milliseconds()),
		Hops: make([]*packet.QuoteDiff, t.maxTTL), Scan: t.target.RawInput,
	}

	addr := net.IPAddr{IP: t.flow.DstIP[:]}
	pkt := t.pktPool.Get().(packet.Packet)
	pkt.PrepareForTrace(t.flow)
	pkt.SetTOS(t.tos)

	var prevQuote packet.Quote
	var timeouts uint8
	wg := &sync.WaitGroup{}
	doneChan := ctx.Done()
	hopTimer := time.NewTimer(traceHopTimeout)

TRACE_LOOP:
	for idx := uint8(0); idx < t.maxTTL; idx++ {
		pkt.SetTTL(idx + 1)
		if _, _, err := t.conn.WriteMsgIP(pkt.Data(), pkt.GetOOB(), addr); err != nil {
			r.Status = statusSendError
			r.Error = err.Error()
			break TRACE_LOOP
		}

		// Wait for new quote packet that is different from previous one
		var q packet.Quote
	WAIT_LOOP:
		for {
			select {
			case q = <-t.quotes:
				if q.Equal(prevQuote) {
					t.mp.PutQuote(q)
					q = nil
					continue WAIT_LOOP
				}
				timeouts = 0 // only count successive timeouts
			case <-hopTimer.C:
				// Skip this hop (q remains nil)
				timeouts++
				if timeouts >= traceMaxTimeouts {
					// We consider hitting traceMaxTimeouts as an indication of
					// either reaching target or encountering an ICMP blackhole
					break TRACE_LOOP
				}
			case <-doneChan:
				r.Status = statusTimeout
				break TRACE_LOOP
			}
			break
		}

		if q != nil {
			if prevQuote != nil {
				t.mp.PutQuote(prevQuote)
			}
			qd := packet.Diff(start, pkt, q)
			prevQuote = q

			// Asynchronously retrieve rDNS entries for QuoteDiff
			wg.Add(1)
			go setHostPTR(ctx, wg, t.resolver, qd)
			r.Hops[idx] = qd

			if q.Source().Equal(addr.IP) {
				// We definitely reached the trace target
				break TRACE_LOOP
			}

			// We didn't receive from hopTimer.C above, so we might need to drain it
			if !hopTimer.Stop() {
				<-hopTimer.C
			}
		}
		hopTimer.Reset(traceHopTimeout)
	}

	hopTimer.Stop()
	if prevQuote != nil {
		t.mp.PutQuote(prevQuote)
	}
	t.pktPool.Put(pkt)
	wg.Wait() // bounded by ctx

	r.DurationMs = uint32(time.Since(start).Milliseconds())
	return json.Marshal(&r)
}

func (t *PacketTrace) drainQuotes() {
	for {
		select {
		case q := <-t.quotes:
			t.mp.PutQuote(q)
		default:
			return
		}
	}
}

func queueingDelay(start time.Time, tgt *TraceboxTarget) time.Duration {
	q := tgt.ScanTime
	if q.IsZero() {
		q = tgt.RcvTime
	}
	qdelay := start.Sub(q)
	if qdelay < 0 {
		log.Printf("negative queueing delay (%s, truncated to 0): %v", qdelay, tgt)
		qdelay = 0
	}
	return qdelay
}

var emptyPTR = []string{}

func setHostPTR(ctx context.Context, wg *sync.WaitGroup, resolver *net.Resolver, qd *packet.QuoteDiff) {
	defer wg.Done()
	var err error

	if qd.HopPTR, err = resolver.LookupAddr(ctx, qd.HopIP.String()); err != nil {
		dnserr, ok := err.(*net.DNSError)
		if !ok || !ignoreDNSError(dnserr) {
			log.Printf("reverse DNS lookup failed: %v", err)
		}
	}

	if qd.HopPTR == nil {
		// Avoid nulls in JSON output
		qd.HopPTR = emptyPTR
	}
}

func ignoreDNSError(e *net.DNSError) bool {
	return e.Err == "no such host" ||
		e.Err == "server misbehaving" ||
		strings.Contains(e.Err, "timeout")
}
