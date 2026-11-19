package inference

import (
	"sync"
	"sync/atomic"

	"capture/internal/flow"
	"capture/internal/metrics"
)

const (
	// DefaultPipelineCapacity is the bounded scoring queue size.
	DefaultPipelineCapacity = 16384
	// ShedThresholdPercent is the fill percentage above which low-risk
	// established flows are dropped instead of blocking capture workers.
	ShedThresholdPercent = 85
	// EstablishedByteThreshold is the byte floor for a flow to count as an
	// established elephant candidate.
	EstablishedByteThreshold = 1_048_576
)

// Pipeline is a bounded ring buffer between the flow shards and the scoring
// workers. Submit never blocks: when the queue is saturated it sheds low-risk
// established flows, and when it is full it drops the flow and counts it.
type Pipeline struct {
	queue     chan flow.Snapshot
	capacity  int
	metricSet *metrics.Metrics

	mu     sync.RWMutex
	closed bool

	dropped atomic.Uint64
	shed    atomic.Uint64
}

// NewPipeline creates a pipeline with the requested capacity. A non-positive
// capacity uses the specification default of 16384. metricSet may be nil.
func NewPipeline(capacity int, metricSet *metrics.Metrics) *Pipeline {
	if capacity <= 0 {
		capacity = DefaultPipelineCapacity
	}
	return &Pipeline{
		queue:     make(chan flow.Snapshot, capacity),
		capacity:  capacity,
		metricSet: metricSet,
	}
}

// IsLowRiskEstablished reports whether a flow is an established, teardown-free
// high-volume conversation. These are the cheapest flows to defer under load.
func IsLowRiskEstablished(snapshot flow.Snapshot) bool {
	return snapshot.SynCnt == 0 &&
		snapshot.FinCnt == 0 &&
		snapshot.RstCnt == 0 &&
		(snapshot.FwdBytes+snapshot.BwdBytes) > EstablishedByteThreshold
}

// Submit admits a completed flow without blocking. Above the 85% watermark a
// low-risk established flow is shed immediately; a full queue rejects any flow.
func (p *Pipeline) Submit(snapshot flow.Snapshot) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		p.dropped.Add(1)
		return false
	}
	if len(p.queue) >= p.capacity*ShedThresholdPercent/100 && IsLowRiskEstablished(snapshot) {
		p.dropped.Add(1)
		p.shed.Add(1)
		p.countDrop()
		return false
	}
	select {
	case p.queue <- snapshot:
		return true
	default:
		p.dropped.Add(1)
		p.countDrop()
		return false
	}
}

// Chan exposes the receive side for the scoring workers.
func (p *Pipeline) Chan() <-chan flow.Snapshot { return p.queue }

// Len returns the current queue depth.
func (p *Pipeline) Len() int { return len(p.queue) }

// Cap returns the configured capacity.
func (p *Pipeline) Cap() int { return p.capacity }

// Dropped returns the number of flows rejected for any reason.
func (p *Pipeline) Dropped() uint64 { return p.dropped.Load() }

// Shed returns the number of low-risk flows shed above the watermark.
func (p *Pipeline) Shed() uint64 { return p.shed.Load() }

// Close stops accepting new flows and closes the receive channel.
func (p *Pipeline) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	close(p.queue)
}

func (p *Pipeline) countDrop() {
	if p.metricSet != nil {
		p.metricSet.FlowsDroppedBackpressure.Inc()
	}
}
