package main

import (
	"bufio"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var buildid = "unknown-dev"
var comsysTool = "ecn-tracebox"
var comsysVP = os.Getenv("VANTAGE_POINT")

func init() {
	// runs after variable initializers
	if len(comsysVP) != 0 {
		comsysTool += "@" + comsysVP
	}
}

type TraceboxConfig struct {
	sampleProb   float64
	tracerCount  uint
	traceIf      string
	traceTimeout time.Duration
	minSrcPort   uint16
	maxTTL       uint8
	traceTOS     uint8
}

func parseFlags() (c TraceboxConfig) {
	var minSrcPort, maxTTL, traceECN uint
	flag.Float64Var(&c.sampleProb, "sample", 1, "input sampling probability (0 to 1)")
	flag.UintVar(&c.tracerCount, "tracers", 500, "number of parallel traces")
	flag.StringVar(&c.traceIf, "interface", "eth0", "network interface to trace on")
	flag.DurationVar(&c.traceTimeout, "timeout", 3*time.Minute, "timeout per trace")
	// Linux by default assigns local ports up to 60999. Our starting value leaves
	// a bit of additional space, just in case. To be absolutely sure that there are
	// no port conflicts, use the net.ipv4.ip_local_reserved_ports sysctl.
	flag.UintVar(&minSrcPort, "sport", 61500, "minimum source port for traces")
	flag.UintVar(&maxTTL, "depth", 40, "maximum trace depth")
	flag.UintVar(&traceECN, "ecn", 0b10, "ECN codepoint to send in traces")

	flag.Parse()
	if c.sampleProb < 0 || c.sampleProb > 1 {
		log.Fatalf("invalid value \"%f\" for -sample: must be between 0 and 1", c.sampleProb)
	}
	if c.tracerCount == 0 {
		log.Fatalln("cannot run with 0 tracers")
	}
	if c.traceTimeout < 30*time.Second {
		log.Fatalf("invalid value %q for -timeout: must be at least 30s", c.traceTimeout)
	}
	if minSrcPort < 1024 {
		log.Fatalf("invalid value \"%d\" for -sport: port range overlaps with system ports", minSrcPort)
	}
	if uint64(minSrcPort)+uint64(c.tracerCount-1) > 0xffff {
		log.Fatalln("not enough source ports available for all tracers")
	}
	if maxTTL < 1 || maxTTL > 255 {
		log.Fatalf("invalid value \"%d\" for -depth: must be between 1 and 255", maxTTL)
	}
	if traceECN&^0b11 != 0 {
		log.Fatalf("invalid value \"%#b\" for -ecn: ECN codepoints are only 2 bits wide", traceECN)
	}

	c.minSrcPort = uint16(minSrcPort)
	c.maxTTL = uint8(maxTTL)
	c.traceTOS = uint8(traceECN)
	return
}

func filterIgnored(sig ...os.Signal) []os.Signal {
	widx := 0
	for _, s := range sig {
		if !signal.Ignored(s) {
			// This is safe: widx <= index(s) always holds
			sig[widx] = s
			widx++
		}
	}
	return sig[:widx]
}

func writer(output io.Writer, lines <-chan []byte) {
	quitsig := make(chan os.Signal, 1)
	if sigs := filterIgnored(os.Interrupt, syscall.SIGHUP, syscall.SIGTERM); len(sigs) != 0 {
		signal.Notify(quitsig, sigs...)
	}
	w := bufio.NewWriterSize(output, zgrabberBufSize)

WRITE_LOOP:
	for {
		select {
		case <-quitsig:
			// Program terminates after writer() exits
			break WRITE_LOOP
		case l, ok := <-lines:
			if !ok {
				break WRITE_LOOP
			}
			w.Write(l) // err will show up below
			if err := w.WriteByte('\n'); err != nil {
				break WRITE_LOOP
			}
			w.Flush()
		}
		// Make sure signal channel isn't starved
		select {
		case <-quitsig:
			break WRITE_LOOP
		default:
		}
	}

	if err := w.Flush(); err != nil {
		log.Panicf("write failed: %v", err)
	}
}

func main() {
	config := parseFlags()
	tc, err := NewTracerCtx(&config)
	if err != nil {
		log.Fatalf("tracer setup failed: %v", err)
	}
	go tc.mp.Run()

	wg := &sync.WaitGroup{}
	input := make(chan *TraceboxTarget, config.tracerCount)
	output := make(chan []byte, config.tracerCount)
	wg.Add(int(config.tracerCount))
	go ZGrabberReader(&config, os.Stdin, input)

	for idx := uint(0); idx < config.tracerCount; idx++ {
		t := tc.NewTracer(wg, &config, input, output)
		go t.Run()
	}

	go func() {
		wg.Wait()
		close(output)
	}()
	writer(os.Stdout, output)
	tc.mp.Stop()
}
