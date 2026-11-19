package flow

import (
	"bytes"
	"errors"
	"sort"
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
// safe for concurrent use: one goroutine owns one Table, which is what removes
// per-flow locking from the packet path.
type Table struct {
	flows map[ingest.FlowKey]*Flow

	// shardClock is the virtual packet clock in epoch microseconds. It only
	// ever moves forward from packet capture timestamps, never from time.Now.
	shardClock      int64
	shardClockSet   bool
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

// ClockUS returns the shard's virtual clock in epoch microseconds.
func (t *Table) ClockUS() int64 { return t.shardClock }

// Process advances the virtual clock, applies timeouts, and folds one packet
// into its flow. The emit callback is invoked zero or more times when a flow
// is evicted or reaches a terminal TCP state.
func (t *Table) Process(p *ingest.Packet, emit func(Snapshot)) {
	if p == nil {
		return
	}
	now := t.advanceShardClock(p.TimestampUS)
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
// Only the expiring flows are sorted, so an empty sweep allocates nothing.
func (t *Table) Sweep(nowUS int64, emit func(Snapshot)) {
	var expired []*Flow
	for _, current := range t.flows {
		if t.expired(current, nowUS) {
			expired = append(expired, current)
		}
	}
	if len(expired) == 0 {
		return
	}
	sortFlows(expired)
	for _, current := range expired {
		emit(current.Snapshot())
		t.delete(current.canonical)
	}
}

// Flush evicts every flow in canonical (start time, five-tuple) order. It is
// called at EOF and on graceful shutdown so output never depends on map order.
func (t *Table) Flush(emit func(Snapshot)) {
	if len(t.flows) == 0 {
		return
	}
	pending := make([]*Flow, 0, len(t.flows))
	for _, current := range t.flows {
		pending = append(pending, current)
	}
	sortFlows(pending)
	for _, current := range pending {
		emit(current.Snapshot())
		t.delete(current.canonical)
	}
}

// advanceShardClock moves the virtual clock forward to the packet timestamp and
// ignores timestamps that would move it backwards.
func (t *Table) advanceShardClock(packetUS int64) int64 {
	if !t.shardClockSet {
		t.shardClockSet = true
		t.shardClock = packetUS
		t.lastSweepUS = packetUS
		return t.shardClock
	}
	if packetUS > t.shardClock {
		t.shardClock = packetUS
	}
	return t.shardClock
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

// sortFlows orders flows by start timestamp, then canonical five-tuple. Keys
// are computed once per flow so the comparison stays allocation-free.
type sortableFlow struct {
	flow    *Flow
	sortKey []byte
}

func sortFlows(flows []*Flow) {
	keyed := make([]sortableFlow, len(flows))
	for i, current := range flows {
		keyed[i] = sortableFlow{flow: current, sortKey: current.canonical.SortKey()}
	}
	sort.Slice(keyed, func(i, j int) bool {
		if keyed[i].flow.startUS != keyed[j].flow.startUS {
			return keyed[i].flow.startUS < keyed[j].flow.startUS
		}
		return bytes.Compare(keyed[i].sortKey, keyed[j].sortKey) < 0
	})
	for i := range keyed {
		flows[i] = keyed[i].flow
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
