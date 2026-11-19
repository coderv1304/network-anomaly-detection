// Package state provides persistent host/window accumulation and a
// circuit-broken alert forwarder for the sensor.
package state

import (
	"context"
	"hash/fnv"
	"log/slog"
	"math"
	"sync"
	"time"
)

// DefaultWindow is the host risk window from the specification.
const DefaultWindow = 5 * time.Minute

// IncidentThreshold is the sliding-window risk-point total that consolidates a
// host's flagged flows into one incident.
const IncidentThreshold = 70.0

// Event is one scored flow contribution to a host window. Risk is expressed in
// the same 0-100 point scale used by the Flask incident accumulator.
type Event struct {
	SourceIP    string
	TimestampUS int64
	Risk        float64
	Label       string
	FlowID      string
}

// WindowSnapshot is the aggregated state of one host window.
type WindowSnapshot struct {
	SourceIP      string
	Count         int
	RiskSum       float64
	Score         float64
	WindowStartUS int64
	WindowEndUS   int64
	Backend       string
}

// WindowStore records flow risk events and returns the current window.
type WindowStore interface {
	Record(ctx context.Context, event Event) (WindowSnapshot, error)
	Backend() string
	Close() error
}

// NewWindowStore returns a Redis-backed store when redisURL is set and
// reachable, otherwise an in-memory sharded store. Redis failures at runtime
// transparently fall back to the in-memory path.
func NewWindowStore(ctx context.Context, redisURL string, window time.Duration, logger *slog.Logger) WindowStore {
	if window <= 0 {
		window = DefaultWindow
	}
	memory := NewMemoryWindowStore(window)
	if redisURL == "" {
		return memory
	}
	redisStore, err := newRedisWindowStore(ctx, redisURL, window, memory, logger)
	if err != nil {
		if logger != nil {
			logger.Warn("redis window state unavailable; using in-memory fallback", "error", err)
		}
		return memory
	}
	return redisStore
}

const memoryShardCount = 64

type MemoryWindowStore struct {
	shards     [memoryShardCount]memoryShard
	windowUS   int64
	maxPerHost int
}

type memoryShard struct {
	mu    sync.Mutex
	hosts map[string]*hostWindow
}

type hostWindow struct {
	events []memoryEvent
	lastUS int64
}

type memoryEvent struct {
	timestampUS int64
	risk        float64
	flowID      string
	label       string
}

func NewMemoryWindowStore(window time.Duration) *MemoryWindowStore {
	acc := &MemoryWindowStore{
		windowUS:   window.Microseconds(),
		maxPerHost: 4096,
	}
	for i := range acc.shards {
		acc.shards[i].hosts = make(map[string]*hostWindow)
	}
	return acc
}

func (a *MemoryWindowStore) Backend() string { return "memory" }

func (a *MemoryWindowStore) Close() error { return nil }

func (a *MemoryWindowStore) Record(_ context.Context, event Event) (WindowSnapshot, error) {
	now := event.TimestampUS
	shard := &a.shards[shardIndex(event.SourceIP)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	host := shard.hosts[event.SourceIP]
	if host == nil {
		host = &hostWindow{}
		shard.hosts[event.SourceIP] = host
	}
	host.lastUS = now
	host.events = pruneMemory(host.events, now-a.windowUS)
	host.events = append(host.events, memoryEvent{
		timestampUS: now,
		risk:        clampRisk(event.Risk),
		flowID:      event.FlowID,
		label:       event.Label,
	})
	if len(host.events) > a.maxPerHost {
		host.events = host.events[len(host.events)-a.maxPerHost:]
	}
	sum := 0.0
	for _, item := range host.events {
		sum += item.risk
	}
	return WindowSnapshot{
		SourceIP:      event.SourceIP,
		Count:         len(host.events),
		RiskSum:       sum,
		Score:         math.Min(100, sum),
		WindowStartUS: now - a.windowUS,
		WindowEndUS:   now,
		Backend:       "memory",
	}, nil
}

func pruneMemory(events []memoryEvent, cutoffUS int64) []memoryEvent {
	cut := 0
	for cut < len(events) && events[cut].timestampUS < cutoffUS {
		cut++
	}
	if cut == 0 {
		return events
	}
	return append(events[:0], events[cut:]...)
}

func clampRisk(risk float64) float64 {
	if math.IsNaN(risk) || math.IsInf(risk, 0) || risk < 0 {
		return 0
	}
	return risk
}

func shardIndex(sourceIP string) int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(sourceIP))
	return int(h.Sum32() % memoryShardCount)
}
