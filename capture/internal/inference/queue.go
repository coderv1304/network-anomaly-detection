package inference

import (
	"sync"
	"sync/atomic"

	"capture/internal/flow"
)

// ShedThresholdPercent is the queue fill percentage above which elephant flows
// are shed before non-blocking enqueue.
const ShedThresholdPercent = 85

// Queue is a bounded ring-buffer around a Go channel. Capture workers never
// block: when the queue is full the flow is dropped and counted.
type Queue struct {
	capacity int
	ch       chan flow.Snapshot

	mu     sync.RWMutex
	closed bool

	dropped atomic.Uint64
}

// NewQueue creates a queue with the requested capacity. Zero uses the
// specification default of 16384.
func NewQueue(capacity int) *Queue {
	if capacity <= 0 {
		capacity = DefaultQueueCapacity
	}
	return &Queue{
		capacity: capacity,
		ch:       make(chan flow.Snapshot, capacity),
	}
}

// Submit attempts a non-blocking enqueue. It returns false when the flow was
// shed because the queue is saturated or the flow is a low-priority elephant
// above the 85% watermark.
func (q *Queue) Submit(snapshot flow.Snapshot) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		q.dropped.Add(1)
		return false
	}
	fill := len(q.ch)
	if q.capacity > 0 && fill*100 >= q.capacity*ShedThresholdPercent && snapshot.IsElephant() {
		q.dropped.Add(1)
		return false
	}
	select {
	case q.ch <- snapshot:
		return true
	default:
		q.dropped.Add(1)
		return false
	}
}

// Chan exposes the receive side for inference workers.
func (q *Queue) Chan() <-chan flow.Snapshot { return q.ch }

// Len returns the current queue depth.
func (q *Queue) Len() int { return len(q.ch) }

// Cap returns the configured capacity.
func (q *Queue) Cap() int { return q.capacity }

// Dropped returns the number of flows shed or rejected on a full queue.
func (q *Queue) Dropped() uint64 { return q.dropped.Load() }

// Close stops accepting new flows and closes the receive channel.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	close(q.ch)
}
