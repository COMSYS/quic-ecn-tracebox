package main

import (
	"math/rand"
	"time"

	"github.com/COMSYS/quic-ecn-tracebox/filter"
	"github.com/die-net/fastrand"
)

type targetFilter struct {
	filter.UniqueIPFilter
	rng        rand.Rand
	prob       float64 // sample if rng.Float64() < prob
	year, week int     // calendar week for filtering
}

func newTargetFilter(config *TraceboxConfig) *targetFilter {
	// Resets on first resetWeekly(), but that's ok
	return &targetFilter{
		UniqueIPFilter: *filter.NewUniqueIPFilter(1_000_000 /* IPv4 */, 250_000 /* IPv6 */),
		rng:            *rand.New(rand.NewSource(int64(fastrand.Uint64()))),
		prob:           config.sampleProb,
	}
}

func (f *targetFilter) resetWeekly(date time.Time) {
	y, w := date.ISOWeek()
	if y != f.year || w != f.week {
		f.year = y
		f.week = w
		f.Reset()
	}
}

func (f *targetFilter) doSample() bool {
	return f.prob >= 1 || f.rng.Float64() < f.prob
}
