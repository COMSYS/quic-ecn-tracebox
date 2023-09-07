package main

import (
	"encoding"
	"encoding/json"
	"time"

	"github.com/COMSYS/quic-ecn-tracebox/packet"
)

type resultStatus uint8

const (
	statusInvalid resultStatus = 0
	statusSuccess resultStatus = iota
	statusTimeout
	statusSendError
)

var _ encoding.TextMarshaler = resultStatus(0)

func (s resultStatus) String() string {
	switch s {
	case statusInvalid:
		return "invalid"
	case statusSuccess:
		return "success"
	case statusTimeout:
		return "timeout"
	case statusSendError:
		return "send_error"
	}
	return "undefined"
}

func (s resultStatus) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

type TraceResult struct {
	TraceTool  string              `json:"comsys-tool"`
	TraceVP    string              `json:"comsys-vp,omitempty"`
	ScanDate   string              `json:"comsys-date,omitempty"`
	ScanSource string              `json:"comsys-source,omitempty"`
	BuildID    string              `json:"commit"` // zgrabber naming convention
	Mode       TraceboxMode        `json:"mode"`
	Status     resultStatus        `json:"status"`
	Trigger    string              `json:"trigger,omitempty"`
	URL        string              `json:"url,omitempty"`
	Flow       packet.IPFlow       `json:"flow"`
	Timestamp  time.Time           `json:"timestamp"`
	DelayMs    uint32              `json:"delay_ms"` // delay between scan and trace
	DurationMs uint32              `json:"duration_ms"`
	Hops       []*packet.QuoteDiff `json:"hops"`
	Error      string              `json:"error,omitempty"`
	Scan       json.RawMessage     `json:"scan,omitempty"`
}
