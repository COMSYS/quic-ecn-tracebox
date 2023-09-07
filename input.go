package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/COMSYS/quic-ecn-tracebox/filter"
	"github.com/buger/jsonparser"
)

type TraceboxTarget struct {
	SrcIP      net.IP // may be nil
	DstIP      net.IP
	URL        string // may be empty
	ScanDate   string // comsys-date
	ScanSource string // comsys-source
	Trigger    string // e.g., ECN validation result for QUIC (may be empty)
	RawInput   []byte
	ScanTime   time.Time
	RcvTime    time.Time // time that ecn-tracebox received the target
	SrcPort    uint16    // may be 0
	DstPort    uint16    // may be 0
	Mode       TraceboxMode
}

func (t *TraceboxTarget) IsIPv4() bool {
	return t.DstIP.To4() != nil
}

func (t *TraceboxTarget) String() string {
	src := net.JoinHostPort(t.SrcIP.String(), strconv.FormatUint(uint64(t.SrcPort), 10))
	dst := net.JoinHostPort(t.DstIP.String(), strconv.FormatUint(uint64(t.DstPort), 10))
	return fmt.Sprintf(
		"mode=%s source=%s url=%s dst=%s src=%s ts=%s",
		t.Mode, t.ScanSource, t.URL, dst, src, t.ScanTime.Format(time.RFC3339),
	)
}

const (
	filterTCP filter.MeasurementSet = 1 << iota
	filterQUIC
)

type zgrabberCtx struct {
	targets chan<- *TraceboxTarget
	filt    *targetFilter
	now     time.Time
}

func (ctx zgrabberCtx) yieldTargets(zgrab []byte) error {
	r, err := newZGrabberResult(zgrab)
	if err != nil {
		if err == errMissingKey {
			return nil
		}
		return err
	}

	if strings.HasPrefix(r.comsysSource, "zmap-") {
		return nil
	}

	// Silently ignore comsys-date parsing errors
	if cd, err := time.Parse("2006-01-02", r.comsysDate); err == nil {
		ctx.filt.resetWeekly(cd)
	}

	if err = ctx.yieldQUICTargets(&r); err != nil {
		return err
	}
	return ctx.yieldTCPTargets(&r)
}

type zgrabberResult struct {
	comsysDate   string
	comsysSource string
	timestamp    time.Time
	dialedAddrs  []dialedAddr
	connInfos    []connInfo
	qlog         []byte
	raw          []byte
}

var errMissingKey = errors.New("JSON input is missing a required key")

func newZGrabberResult(json []byte) (res zgrabberResult, err error) {
	res.raw = cloneBytes(json)
	keys := [][]string{
		{"comsys-date"},
		{"comsys-source"},
		{"zgrab", "data", "http", "timestamp"},
		{"zgrab", "data", "http", "result", "dialed_addrs"},
		{"zgrab", "data", "http", "result", "conn_infos"},
		{"zgrab", "data", "http", "result", "qlog"},
	}
	reqKeys := 3
	cnt := jsonparser.EachKey(res.raw, func(idx int, val []byte, _ jsonparser.ValueType, err2 error) {
		if err != nil {
			return // skip remaining keys
		}
		if err2 != nil {
			err = err2
			return
		}

		switch idx {
		case 0: // .["comsys-date"]
			res.comsysDate, err = jsonparser.ParseString(val)
			reqKeys--
		case 1: // .["comsys-source"]
			res.comsysSource, err = jsonparser.ParseString(val)
			reqKeys--
		case 2: // .zgrab.data.http.timestamp
			// Timestamp can't contain escaped characters
			res.timestamp, err = time.Parse(time.RFC3339, string(val))
			reqKeys--
		case 3: // .zgrab.data.http.result.dialed_addrs
			res.dialedAddrs, err = parseDialedAddrs(val)
		case 4: // .zgrab.data.http.result.conn_infos
			res.connInfos, err = parseConnInfos(val)
		case 5: // .zgrab.data.http.result.qlog
			res.qlog = val
		default:
			log.Panicf("unexpected field index %d in newZGrabberResult", idx)
		}
	}, keys...)

	if err == nil && cnt == -1 && reqKeys > 0 {
		err = errMissingKey
	}
	return
}

type dialedAddr struct {
	data []byte
}

func parseDialedAddrs(arr []byte) (res []dialedAddr, err error) {
	_, err = jsonparser.ArrayEach(arr, func(data []byte, _ jsonparser.ValueType, _ int, _ error) {
		res = append(res, dialedAddr{data: data})
	})
	return
}

func (a dialedAddr) IP() (netip.Addr, error) {
	ip, err := jsonparser.GetUnsafeString(a.data, "IP")
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(ip)
}

func (a dialedAddr) URL() string {
	host, _ := jsonparser.GetUnsafeString(a.data, "Host")
	if host == "" {
		return ""
	}
	return fmt.Sprintf("https://%s", host)
}

type connInfo struct {
	ect0, ect1      uint32 // optional
	synackEcecwr    uint32 // optional
	sport           uint16 // optional
	options         uint8
	ecnFallback     bool // optional
	valid           bool
	packetsEcecwr   uint32 // optional
	packetsNoececwr uint32 // optional
	packetsEcenocwr uint32 // optional
}

func parseConnInfo(ci []byte) (res connInfo) {
	keys := [][]string{
		{"Options"}, {"Packets_Ect0"}, {"Packets_Ect1"},
		{"Synack_Ececwr"}, {"SrcPort"}, {"Ecn_Fallback"},
		{"Packets_Ececwr"}, {"Packets_Noececwr"}, {"Packets_Ecenocwr"},
	}
	jsonparser.EachKey(ci, func(idx int, val []byte, vt jsonparser.ValueType, err error) {
		if err != nil {
			return
		}
		var v int64
		switch idx {
		case 5: // .Ecn_Fallback
			if vt != jsonparser.Boolean {
				return
			}
		default:
			if vt != jsonparser.Number {
				return
			}
			v, err = jsonparser.ParseInt(val)
			if err != nil || v < 0 {
				return
			}
		}

		switch idx {
		case 0: // .Options
			if v <= math.MaxUint8 {
				res.options = uint8(v)
				res.valid = true
			}
		case 1: // .Packets_Ect0
			if v <= math.MaxUint32 {
				res.ect0 = uint32(v)
			}
		case 2: // .Packets_Ect1
			if v <= math.MaxUint32 {
				res.ect1 = uint32(v)
			}
		case 3: // .Synack_Ececwr
			if v <= math.MaxUint32 {
				res.synackEcecwr = uint32(v)
			}
		case 4: // .SrcPort
			if v <= math.MaxUint16 {
				res.sport = uint16(v)
			}
		case 5: // .Ecn_Fallback
			if string(val) == "true" {
				res.ecnFallback = true
			}
		case 6: // .Packets_Ececwr
			if v <= math.MaxUint32 {
				res.packetsEcecwr = uint32(v)
			}
		case 7: // .Packets_Noececwr
			if v <= math.MaxUint32 {
				res.packetsNoececwr = uint32(v)
			}
		case 8: // .Packets_Ecenocwr
			if v <= math.MaxUint32 {
				res.packetsEcenocwr = uint32(v)
			}
		default:
			log.Panicf("unexpected field index %d in parseConnInfo", idx)
		}
	}, keys...)
	return
}

func parseConnInfos(arr []byte) (res []connInfo, err error) {
	_, err = jsonparser.ArrayEach(arr, func(data []byte, _ jsonparser.ValueType, _ int, _ error) {
		res = append(res, parseConnInfo(data))
	})
	return
}

// From <linux/tcp.h>
const (
	tcpInfoEcnNeg  uint8 = 8
	tcpInfoEcnSeen uint8 = 16
)

func (ci connInfo) traceTrigger() string {
	if ci.ecnFallback {
		return "fallback"
	}
	switch ci.options & (tcpInfoEcnNeg | tcpInfoEcnSeen) {
	case 0, tcpInfoEcnSeen:
		return "noecn"
	case tcpInfoEcnNeg:
		return "noecnseen"
	}

	//enable only for CE testcases!
	//if (ci.packetsEcenocwr + ci.packetsEcecwr) == 0 {
	//	return "noece"
	//}

	if ci.ect1 > 0 {
		return "ect1_seen"
	}
	if ci.synackEcecwr > 0 {
		return "synack_ececwr_seen"
	}
	return ""
}

func (ctx zgrabberCtx) yieldTCPTargets(r *zgrabberResult) error {
	if r.dialedAddrs == nil || r.connInfos == nil {
		return nil
	}
	tgts := len(r.dialedAddrs)
	if tgts == 0 || tgts != len(r.connInfos) {
		log.Printf("detected discrepancy between dialed_addrs (len %d) and conn_infos (len %d)", tgts, len(r.connInfos))
		return nil
	}

	for idx := 0; idx < tgts; idx++ {
		ci := r.connInfos[idx]
		da := r.dialedAddrs[idx]
		if !ci.valid {
			continue
		}

		ip, err := da.IP()
		if err != nil {
			log.Printf("parsing dialed_addrs IP failed: %v", err)
			continue
		}
		if ctx.filt.Peek(ip, filterTCP) {
			continue
		}

		trigger := ci.traceTrigger()
		if trigger == "" {
			if !ctx.filt.doSample() {
				continue
			}
			trigger = "random_sample"
		}
		ctx.filt.Merge(ip, filterTCP)
		ctx.targets <- &TraceboxTarget{
			SrcIP: nil, DstIP: ip.AsSlice(), URL: da.URL(),
			ScanDate: r.comsysDate, ScanSource: r.comsysSource,
			Trigger: trigger, RawInput: r.raw,
			ScanTime: r.timestamp, RcvTime: ctx.now,
			SrcPort: ci.sport, DstPort: 0, Mode: TraceboxTCP,
		}
	}
	return nil
}

type qlogConnStart struct {
	data   []byte
	url    *url.URL
	_dstIP netip.Addr
}

func (c *qlogConnStart) dstIP() netip.Addr {
	if !c._dstIP.IsValid() {
		ip, _ := jsonparser.GetUnsafeString(c.data, "dst_ip")
		c._dstIP, _ = netip.ParseAddr(ip)
	}
	return c._dstIP
}

func (c *qlogConnStart) toTraceboxTarget(r *zgrabberResult, now time.Time, trigger string) *TraceboxTarget {
	dstIP := c.dstIP().AsSlice()
	if dstIP == nil {
		return nil
	}
	srcIP, _ := jsonparser.GetUnsafeString(c.data, "src_ip")
	srcPort, _ := jsonparser.GetInt(c.data, "src_port")
	dstPort, _ := jsonparser.GetInt(c.data, "dst_port")

	return &TraceboxTarget{
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      dstIP,
		URL:        c.url.String(),
		ScanDate:   r.comsysDate,
		ScanSource: r.comsysSource,
		Trigger:    trigger,
		RawInput:   r.raw,
		ScanTime:   r.timestamp,
		RcvTime:    now,
		SrcPort:    uint16(srcPort),
		DstPort:    uint16(dstPort),
		Mode:       TraceboxQUIC,
	}
}

type kvEntry struct {
	name  string
	value []byte
	conn  string
}

func parseKVEntry(kv []byte) (res kvEntry, err error) {
	keys := [][]string{{"Name"}, {"Value"}, {"Conn"}}
	jsonparser.EachKey(kv, func(idx int, val []byte, _ jsonparser.ValueType, err2 error) {
		if err != nil {
			return // skip remaining keys
		}
		if err2 != nil {
			err = err2
			return
		}

		switch idx {
		case 0:
			res.name, err = jsonparser.ParseString(val)
		case 1:
			res.value = val
		case 2:
			res.conn, err = jsonparser.ParseString(val)
		default:
			log.Panicf("unexpected field index %d in parseKVEntry", idx)
		}
	}, keys...)

	if err == nil && res.name == "qlog" {
		if string(res.value) == `\n` {
			res.value = nil
		} else {
			res.value, err = jsonparser.Unescape(res.value, nil)
		}
	}
	return
}

// ECN validation results for which to run a trace
// We include successful results here as a reference measurement
var quicTraceECNResults = map[string]bool{
	"illegal_remarking_ect0": true, "illegal_remarking_ect1": true,
	"missing_mark_ect0": true, "missing_mark_ect1": true, "missing_mark_ce": true,
	"all_sent_ce": true, "all_sent_lost": true, "success": true, "missing_counters": true,
}

func (ctx zgrabberCtx) yieldQUICTargets(r *zgrabberResult) error {
	if r.qlog == nil {
		return nil
	}
	return jsonparser.ObjectEach(r.qlog, func(_, kvlog []byte, vt jsonparser.ValueType, _ int) error {
		if vt != jsonparser.Array {
			return nil
		}
		breakLoop := false
		var cur_url *url.URL
		conns := make(map[string]qlogConnStart)

		_, err2 := jsonparser.ArrayEach(kvlog, func(entry []byte, _ jsonparser.ValueType, _ int, _ error) {
			if breakLoop {
				return
			}

			kv, err := parseKVEntry(entry)
			if err != nil {
				log.Printf("parsing qlog entry failed: %v", err)
				breakLoop = true
				return
			}

			switch kv.name {
			case "qlog":
				// Handled separately below
			case "url":
				new_url, err := jsonparser.ParseString(kv.value) // err intentionally ignored
				if cur_url, err = url.Parse(new_url); err != nil {
					log.Printf("parsing initial URL failed: %v", err)
					breakLoop = true
				}
				return
			case "redirect":
				var err error
				if cur_url, err = getRedirectURL(kv.value, cur_url); err != nil {
					log.Printf("redirecting URL failed: %v", err)
					breakLoop = true
				}
				return
			default:
				return // ignore
			}

			if len(kv.conn) == 0 || len(kv.value) == 0 {
				return
			}
			eventName, _ := jsonparser.GetString(kv.value, "name")

			switch eventName {
			case "transport:connection_started", "connectivity:connection_started":
				if _, ok := conns[kv.conn]; ok {
					break
				}
				if cur_url == nil {
					log.Println("saving QUIC/h3 connection failed: missing URL")
					breakLoop = true
					return
				}
				eventData, _, _, err := jsonparser.Get(kv.value, "data")
				if err != nil {
					log.Printf("parsing qlog event failed: %v", err)
					break
				}
				conns[kv.conn] = qlogConnStart{data: eventData, url: cur_url}
			case "transport:ecn_validated":
				c, ok := conns[kv.conn]
				if !ok {
					break
				}
				ip := c.dstIP()
				if ctx.filt.Peek(ip, filterQUIC) {
					delete(conns, kv.conn)
					break
				}

				reason, _ := jsonparser.GetString(kv.value, "data", "reason")
				if reason == "" {
					reason = "success"
				}
				if !quicTraceECNResults[reason] {
					if !ctx.filt.doSample() {
						break
					}
					reason = "random_sample"
				}
				if tgt := c.toTraceboxTarget(r, ctx.now, reason); tgt != nil {
					ctx.filt.Merge(ip, filterQUIC)
					ctx.targets <- tgt
				}
				delete(conns, kv.conn)
			}
		})
		return err2
	})
}

var errMissingBase = errors.New("missing base URL")
var errMissingLocation = errors.New("missing Location header")

func getRedirectURL(redirect []byte, cur_url *url.URL) (*url.URL, error) {
	if cur_url == nil {
		return nil, errMissingBase
	}
	loc, err := jsonparser.GetString(redirect, "Header", "Location", "[0]")
	if err != nil {
		return nil, errMissingLocation
	}
	return cur_url.Parse(loc)
}

func stripPubsubHeader(line []byte) []byte {
	// rabbit-pubsub-stdinout header is a decimal number followed by a '|'.
	// Assume the header is at most 32 bytes long, which allows for 10^31 - 1
	// parallel pubsub messages (>> 2^64, i.e., not gonna happen).
	head := line
	if len(line) > 32 {
		head = line[:32]
	}
	sep := bytes.IndexByte(head, '|')
	if sep < 0 {
		return line // no header
	}
	for _, b := range head[:sep] {
		if !('0' <= b && b <= '9') {
			return line // '|' is part of payload
		}
	}
	return line[sep+1:]
}

const (
	zgrabberBufSize = 1024 * 1024        // 1MB
	zgrabberMaxBuf  = 1024 * 1024 * 1024 // 1GB
)

func ZGrabberReader(config *TraceboxConfig, input io.Reader, targets chan<- *TraceboxTarget) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, zgrabberBufSize), zgrabberMaxBuf)
	filt := newTargetFilter(config)

	for scanner.Scan() {
		ctx := zgrabberCtx{targets: targets, filt: filt, now: time.Now()}
		// On external VPs, we want to handle the zgrabber's output directly,
		// e.g., via tee (including the rabbit-pubsub-stdinout header)
		line := stripPubsubHeader(scanner.Bytes())
		if err := ctx.yieldTargets(line); err != nil {
			log.Printf("parsing zgrabber result failed: %v", err)
			continue
		}
	}

	close(targets)
	if err := scanner.Err(); err != nil {
		log.Printf("read failed: %v", err)
	}
}
