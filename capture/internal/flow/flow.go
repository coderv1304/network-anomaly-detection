// Package flow implements a sharded bidirectional flow table driven by a
// virtual packet clock and the exact feature math shared by extraction and
// live inference.
package flow

import (
	"math"

	"capture/internal/ingest"
)

const (
	microsPerSecond int64 = 1_000_000
)

// Flow is the mutable per-conversation state owned by exactly one shard.
// No mutex is needed because only that shard's goroutine touches it.
type Flow struct {
	canonical  ingest.FlowKey
	initialKey ingest.FlowKey

	// Forward anchor. The initial packet defines it; a mid-stream reverse SYN
	// flips it to the true TCP initiator.
	fwd ingest.Endpoint

	startUS    int64
	lastUS     int64
	lastFwdUS  int64
	lastBwdUS  int64
	firstSeqUS int64

	fwdPkts    uint64
	bwdPkts    uint64
	fwdBytes   uint64
	bwdBytes   uint64
	fwdHdrByte uint64
	bwdHdrByte uint64

	finCnt uint64
	synCnt uint64
	rstCnt uint64
	pshCnt uint64
	ackCnt uint64
	urgCnt uint64
	eceCnt uint64
	cwrCnt uint64

	fwdPSH uint64
	bwdPSH uint64
	fwdURG uint64
	bwdURG uint64

	flowIAT      Welford
	fwdIAT       Welford
	bwdIAT       Welford
	flowIATTotal int64

	fwdLen Welford
	bwdLen Welford
	allLen Welford

	initFwdWin uint16
	initBwdWin uint16

	fwdPayloadPkts uint64

	sawFwdSYN bool
	finFwd    bool
	finBwd    bool
}

// NewFlow creates a flow anchored to the first observed packet.
func NewFlow(p *ingest.Packet) *Flow {
	key := p.Key()
	return &Flow{
		canonical:  key.Canonical(),
		initialKey: key,
		fwd:        ingest.Endpoint{IP: p.SrcIP, Port: p.SrcPort},
		startUS:    p.TimestampUS,
		lastUS:     p.TimestampUS,
		firstSeqUS: p.TimestampUS,
	}
}

// Key returns the canonical conversation key.
func (f *Flow) Key() ingest.FlowKey { return f.canonical }

// StartUS returns the first packet timestamp in epoch microseconds.
func (f *Flow) StartUS() int64 { return f.startUS }

// LastSeenUS returns the most recent packet timestamp in epoch microseconds.
func (f *Flow) LastSeenUS() int64 { return f.lastUS }

// IsForward reports whether the packet travels in the anchored forward
// direction.
func (f *Flow) IsForward(p *ingest.Packet) bool {
	return p.SrcIP == f.fwd.IP && p.SrcPort == f.fwd.Port
}

// AddPacket updates counters and statistics for one packet. It returns true
// when the flow reached a terminal state and should be emitted immediately.
func (f *Flow) AddPacket(p *ingest.Packet) bool {
	forward := f.IsForward(p)

	// Mid-stream capture: the first packet seen may belong to the responder.
	// A reverse SYN without ACK identifies the true initiator; flip before
	// counting so every directional feature stays consistent.
	if !forward && p.Proto == ingest.ProtoTCP && p.HasFlag(ingest.TCPFlagSYN) && !p.HasFlag(ingest.TCPFlagACK) && !f.sawFwdSYN {
		f.flipDirection()
		forward = true
	}

	if forward {
		f.fwdPkts++
		f.fwdBytes += uint64(maxInt(p.Length, 0))
		f.fwdHdrByte += uint64(maxInt(p.HeaderLen, 0))
		f.fwdLen.Add(float64(p.Length))
		if p.Proto == ingest.ProtoTCP && p.HasFlag(ingest.TCPFlagSYN) && !p.HasFlag(ingest.TCPFlagACK) {
			f.sawFwdSYN = true
		}
		if p.PayloadLen > 0 {
			f.fwdPayloadPkts++
		}
		if f.initFwdWin == 0 {
			f.initFwdWin = p.TCPWindow
		}
	} else {
		f.bwdPkts++
		f.bwdBytes += uint64(maxInt(p.Length, 0))
		f.bwdHdrByte += uint64(maxInt(p.HeaderLen, 0))
		f.bwdLen.Add(float64(p.Length))
		if f.initBwdWin == 0 || p.TCPWindow != 0 {
			f.initBwdWin = p.TCPWindow
		}
	}
	f.allLen.Add(float64(p.Length))

	if p.Proto == ingest.ProtoTCP {
		f.countFlags(p, forward)
	}

	// Inter-arrival times use the monotonic packet clock. Out-of-order capture
	// timestamps are clamped to zero instead of producing a negative sample.
	if f.lastUS != 0 || f.firstSeqUS != 0 {
		delta := p.TimestampUS - f.lastUS
		if delta < 0 {
			delta = 0
		}
		if f.fwdPkts+f.bwdPkts > 1 {
			f.flowIAT.Add(float64(delta))
			f.flowIATTotal += delta
			if forward {
				f.fwdIAT.Add(float64(delta))
			} else {
				f.bwdIAT.Add(float64(delta))
			}
		}
	}
	if forward {
		f.lastFwdUS = p.TimestampUS
	} else {
		f.lastBwdUS = p.TimestampUS
	}
	if p.TimestampUS > f.lastUS {
		f.lastUS = p.TimestampUS
	}

	if p.Proto != ingest.ProtoTCP {
		return false
	}
	if p.HasFlag(ingest.TCPFlagRST) {
		return true
	}
	if forward && p.HasFlag(ingest.TCPFlagFIN) {
		f.finFwd = true
	}
	if !forward && p.HasFlag(ingest.TCPFlagFIN) {
		f.finBwd = true
	}
	return f.finFwd && f.finBwd
}

func (f *Flow) countFlags(p *ingest.Packet, forward bool) {
	if p.HasFlag(ingest.TCPFlagFIN) {
		f.finCnt++
	}
	if p.HasFlag(ingest.TCPFlagSYN) {
		f.synCnt++
	}
	if p.HasFlag(ingest.TCPFlagRST) {
		f.rstCnt++
	}
	if p.HasFlag(ingest.TCPFlagPSH) {
		f.pshCnt++
		if forward {
			f.fwdPSH++
		} else {
			f.bwdPSH++
		}
	}
	if p.HasFlag(ingest.TCPFlagACK) {
		f.ackCnt++
	}
	if p.HasFlag(ingest.TCPFlagURG) {
		f.urgCnt++
		if forward {
			f.fwdURG++
		} else {
			f.bwdURG++
		}
	}
	if p.HasFlag(ingest.TCPFlagECE) {
		f.eceCnt++
	}
	if p.HasFlag(ingest.TCPFlagCWR) {
		f.cwrCnt++
	}
}

// flipDirection swaps the forward and backward anchors and all directional
// accumulators. Whole-flow counters are unaffected.
func (f *Flow) flipDirection() {
	if f.fwd == f.canonical.Src {
		f.fwd = f.canonical.Dst
	} else {
		f.fwd = f.canonical.Src
	}
	f.fwdPkts, f.bwdPkts = f.bwdPkts, f.fwdPkts
	f.fwdBytes, f.bwdBytes = f.bwdBytes, f.fwdBytes
	f.fwdHdrByte, f.bwdHdrByte = f.bwdHdrByte, f.fwdHdrByte
	f.fwdPSH, f.bwdPSH = f.bwdPSH, f.fwdPSH
	f.fwdURG, f.bwdURG = f.bwdURG, f.fwdURG
	f.fwdIAT, f.bwdIAT = f.bwdIAT, f.fwdIAT
	f.fwdLen, f.bwdLen = f.bwdLen, f.fwdLen
	f.lastFwdUS, f.lastBwdUS = f.lastBwdUS, f.lastFwdUS
	f.finFwd, f.finBwd = f.finBwd, f.finFwd
	f.initFwdWin, f.initBwdWin = f.initBwdWin, f.initFwdWin
	// Payload-packet accounting is only kept for the forward side; the
	// previously forward packets are now backward by definition.
	f.fwdPayloadPkts = 0
}

// Snapshot returns an immutable copy of the flow for serialization or scoring.
func (f *Flow) Snapshot() Snapshot {
	return Snapshot{
		Key:            f.canonical,
		InitialKey:     f.initialKey,
		ForwardKey:     f.forwardKey(),
		StartUS:        f.startUS,
		EndUS:          f.lastUS,
		FwdPkts:        f.fwdPkts,
		BwdPkts:        f.bwdPkts,
		FwdBytes:       f.fwdBytes,
		BwdBytes:       f.bwdBytes,
		FwdHdrBytes:    f.fwdHdrByte,
		BwdHdrBytes:    f.bwdHdrByte,
		FinCnt:         f.finCnt,
		SynCnt:         f.synCnt,
		RstCnt:         f.rstCnt,
		PshCnt:         f.pshCnt,
		AckCnt:         f.ackCnt,
		UrgCnt:         f.urgCnt,
		EceCnt:         f.eceCnt,
		CwrCnt:         f.cwrCnt,
		FwdPSHCnt:      f.fwdPSH,
		BwdPSHCnt:      f.bwdPSH,
		FwdURGCnt:      f.fwdURG,
		BwdURGCnt:      f.bwdURG,
		FlowIATTotalUS: f.flowIATTotal,
		FlowIAT:        f.flowIAT.Summary(),
		FwdIAT:         f.fwdIAT.Summary(),
		BwdIAT:         f.bwdIAT.Summary(),
		FwdLen:         f.fwdLen.Summary(),
		BwdLen:         f.bwdLen.Summary(),
		AllLen:         f.allLen.Summary(),
		InitFwdWin:     f.initFwdWin,
		InitBwdWin:     f.initBwdWin,
		FwdPayloadPkts: f.fwdPayloadPkts,
		SawFwdSYN:      f.sawFwdSYN,
		FinFwd:         f.finFwd,
		FinBwd:         f.finBwd,
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (f *Flow) forwardKey() ingest.FlowKey {
	src, dst := f.canonical.Src, f.canonical.Dst
	if f.fwd != f.canonical.Src {
		src, dst = dst, src
	}
	return ingest.FlowKey{
		Src:    src,
		Dst:    dst,
		Proto:  f.canonical.Proto,
		IsIPv6: f.canonical.IsIPv6,
	}
}

// clampNonNegative returns value or zero, whichever is larger.
func clampNonNegative(value float64) float64 {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}
