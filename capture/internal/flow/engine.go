package flow

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"capture/internal/ingest"
)

const (
	// DefaultIdleTimeout matches the sensor specification.
	DefaultIdleTimeout = 15 * time.Second
	// DefaultActiveTimeout matches the sensor specification.
	DefaultActiveTimeout = 120 * time.Second
	// DefaultSweepInterval is the virtual-time granularity of timeout sweeps.
	DefaultSweepInterval = 1 * time.Second
)

// ErrEngineClosed is returned when a packet is submitted after Close.
var ErrEngineClosed = errors.New("flow engine is closed")

// Table is a single-shard bidirectional flow table. It is intentionally not
// safe for concurrent use: one goroutine owns one Table.
type Table struct {
	flows map[ingest.FlowKey]*Flow

	clockUS         int64
	clockSet        bool
	lastSweepUS     int64
	idleTimeoutUS   int64
	activeTimeoutUS int64
	sweepIntervalUS int64

	active atomic.Int64
}

// NewTable creates an empty shard with the supplied timeouts.
func NewTable(idle, active time.Duration) *Table {
	if idle <= 0 {
		idle = DefaultIdleTimeout
	}
	if active <= 0 {
		active = DefaultActiveTimeout
	}
	return &Table{
		flows:           make(map[ingest.FlowKey]*Flow),
		idleTimeoutUS:   idle.Microseconds(),
		activeTimeoutUS: active.Microseconds(),
		sweepIntervalUS: DefaultSweepInterval.Microseconds(),
	}
}

// Len returns the number of active flows in the shard.
func (t *Table) Len() int { return int(t.active.Load()) }

// ClockUS returns the shard's virtual clock.
func (t *Table) ClockUS() int64 { return t.clockUS }

// Process advances the virtual clock, applies timeouts, and folds one packet
// into its flow. The emit callback is invoked zero or more times when a flow
// is evicted or reaches a terminal TCP state.
func (t *Table) Process(p *ingest.Packet, emit func(Snapshot)) {
	if p == nil {
		return
	}
	now := t.advanceClock(p.TimestampUS)
	t.maybeSweep(now, emit)

	key := p.Key().Canonical()
	if existing, ok := t.flows[key]; ok {
		if t.expired(existing, now) {
			emit(existing.Snapshot())
			t.delete(key)
		}
	}
	current, ok := t.flows[key]
	if !ok {
		current = NewFlow(p)
		t.flows[key] = current
		t.active.Add(1)
	}
	if current.AddPacket(p) {
		emit(current.Snapshot())
		t.delete(key)
	}
}

// Sweep evicts idle and active flows relative to the supplied virtual time.
func (t *Table) Sweep(nowUS int64, emit func(Snapshot)) {
	for key, current := range t.flows {
		if t.expired(current, nowUS) {
			emit(current.Snapshot())
			delete(t.flows, key)
			t.active.Add(-1)
		}
	}
}

// Flush evicts every flow. It is called at EOF and on graceful shutdown.
func (t *Table) Flush(emit func(Snapshot)) {
	for key, current := range t.flows {
		emit(current.Snapshot())
		delete(t.flows, key)
		t.active.Add(-1)
	}
}

func (t *Table) advanceClock(packetUS int64) int64 {
	if !t.clockSet {
		t.clockSet = true
		t.clockUS = packetUS
		t.lastSweepUS = packetUS
		return t.clockUS
	}
	if packetUS > t.clockUS {
		t.clockUS = packetUS
	}
	return t.clockUS
}

func (t *Table) maybeSweep(nowUS int64, emit func(Snapshot)) {
	if nowUS-t.lastSweepUS < t.sweepIntervalUS {
		return
	}
	t.Sweep(nowUS, emit)
	t.lastSweepUS = nowUS
}

func (t *Table) expired(current *Flow, nowUS int64) bool {
	if nowUS-current.lastUS >= t.idleTimeoutUS {
		return true
	}
	return nowUS-current.startUS >= t.activeTimeoutUS
}

func (t *Table) delete(key ingest.FlowKey) {
	if _, ok := t.flows[key]; ok {
		delete(t.flows, key)
		t.active.Add(-1)
	}
}

// Engine owns one Table per worker goroutine. Packets are routed by the
// canonical five-tuple hash, so all packets of a conversation are processed by
// exactly one goroutine without any shared-flow locks.
type Engine struct {
	tables  []*Table
	inputs  []chan ingest.Packet
	emit    func(Snapshot)
	done    chan struct{}
	closed  atomic.Bool
	wg      sync.WaitGroup
	started bool
}

// NewEngine creates a sharded engine. emit may be called concurrently from
// multiple worker goroutines.
func NewEngine(workers int, idle, active time.Duration, emit func(Snapshot)) *Engine {
	if workers < 1 {
		workers = 1
	}
	if emit == nil {
		emit = func(Snapshot) {}
	}
	engine := &Engine{
		tables: make([]*Table, workers),
		inputs: make([]chan ingest.Packet, workers),
		emit:   emit,
		done:   make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		engine.tables[i] = NewTable(idle, active)
		engine.inputs[i] = make(chan ingest.Packet, 4096)
	}
	return engine
}

// Start launches one worker per shard.
func (e *Engine) Start() {
	if e.started {
		return
	}
	e.started = true
	for i := range e.tables {
		table := e.tables[i]
		input := e.inputs[i]
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for packet := range input {
				table.Process(&packet, e.emit)
			}
			table.Flush(e.emit)
		}()
	}
}

// Process routes one packet to its shard. It blocks only when that shard's
// bounded input buffer is full, which applies natural backpressure to the
// capture reader.
func (e *Engine) Process(packet ingest.Packet) error {
	if e.closed.Load() {
		return ErrEngineClosed
	}
	select {
	case <-e.done:
		return ErrEngineClosed
	default:
	}
	index := packet.Key().ShardIndex(len(e.tables))
	select {
	case e.inputs[index] <- packet:
		return nil
	case <-e.done:
		return ErrEngineClosed
	}
}

// Close drains every shard and flushes all remaining flows.
func (e *Engine) Close() {
	if e.closed.Swap(true) {
		return
	}
	close(e.done)
	for _, input := range e.inputs {
		close(input)
	}
	e.wg.Wait()
}

// ActiveFlows returns the sum of active flows across shards.
func (e *Engine) ActiveFlows() int {
	total := 0
	for _, table := range e.tables {
		total += table.Len()
	}
	return total
}
