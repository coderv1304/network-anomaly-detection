package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Alert is one flagged flow ready for the Flask console.
type Alert struct {
	FlowID      string
	SourceIP    string
	Risk        float64
	TimestampUS int64
	Payload     map[string]any
}

// BatchAlertSinkOptions configures the batched alert sink.
type BatchAlertSinkOptions struct {
	URL              string
	APIKey           string
	Client           *http.Client
	BatchSize        int
	FlushInterval    time.Duration
	QueueCapacity    int
	BackoffBase      time.Duration
	MaxBackoff       time.Duration
	BreakerThreshold int
	BreakerCooldown  time.Duration
	Logger           *slog.Logger
}

// BatchAlertSink batches flagged flows and consolidated host incidents and
// posts them to the Flask ingest endpoint. It never blocks capture workers and
// uses a circuit breaker so a console outage cannot become a retry storm.
type BatchAlertSink struct {
	opts BatchAlertSinkOptions
	url  string

	queue  chan Alert
	mu     sync.RWMutex
	closed bool

	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	sent     atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64
	failures atomic.Int32

	nextAttempt atomic.Int64
	openUntil   atomic.Int64
}

// NewForwarder validates options and creates the sink. Start must be called
// before Enqueue.
func NewBatchAlertSink(opts BatchAlertSinkOptions) (*BatchAlertSink, error) {
	if opts.URL == "" {
		return nil, errors.New("alert forwarder requires a URL")
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = 256
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = 2 * time.Second
	}
	if opts.QueueCapacity <= 0 {
		opts.QueueCapacity = 4096
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = 100 * time.Millisecond
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 5 * time.Second
	}
	if opts.BreakerThreshold <= 0 {
		opts.BreakerThreshold = 5
	}
	if opts.BreakerCooldown <= 0 {
		opts.BreakerCooldown = 30 * time.Second
	}
	return &BatchAlertSink{
		opts:  opts,
		url:   opts.URL,
		queue: make(chan Alert, opts.QueueCapacity),
	}, nil
}

// Start launches the batch loop.
func (f *BatchAlertSink) Start(parent context.Context) {
	f.mu.Lock()
	if f.started {
		f.mu.Unlock()
		return
	}
	f.started = true
	ctx, cancel := context.WithCancel(parent)
	f.cancel = cancel
	f.mu.Unlock()

	f.wg.Add(1)
	go f.loop(ctx)
}

// Enqueue admits an alert without blocking. It returns false when the queue is
// full or the forwarder is shutting down.
func (f *BatchAlertSink) Enqueue(alert Alert) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed {
		f.dropped.Add(1)
		return false
	}
	select {
	case f.queue <- alert:
		return true
	default:
		f.dropped.Add(1)
		return false
	}
}

// Sent returns the number of alerts acknowledged by the receiver.
func (f *BatchAlertSink) Sent() uint64 { return f.sent.Load() }

// Dropped returns the number of alerts rejected by queue or breaker limits.
func (f *BatchAlertSink) Dropped() uint64 { return f.dropped.Load() }

// Failed returns the number of send attempts that were not acknowledged.
func (f *BatchAlertSink) Failed() uint64 { return f.failed.Load() }

// Close drains the queue and performs one final best-effort flush.
func (f *BatchAlertSink) Close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	started := f.started
	close(f.queue)
	f.mu.Unlock()

	if started {
		f.wg.Wait()
	}
	if f.cancel != nil {
		f.cancel()
	}
}

func (f *BatchAlertSink) loop(ctx context.Context) {
	defer f.wg.Done()
	ticker := time.NewTicker(f.opts.FlushInterval)
	defer ticker.Stop()
	pending := make([]Alert, 0, f.opts.BatchSize)
	maxPending := f.opts.BatchSize * 8

	for {
		select {
		case <-ctx.Done():
			f.drain(&pending, maxPending)
			f.flush(&pending)
			return
		case alert, ok := <-f.queue:
			if !ok {
				f.drain(&pending, maxPending)
				f.flush(&pending)
				return
			}
			pending = append(pending, alert)
			if len(pending) > maxPending {
				drop := len(pending) - maxPending
				pending = append(pending[:0], pending[drop:]...)
				f.dropped.Add(uint64(drop))
			}
			if len(pending) >= f.opts.BatchSize {
				f.flush(&pending)
			}
		case <-ticker.C:
			f.flush(&pending)
		}
	}
}

func (f *BatchAlertSink) drain(pending *[]Alert, maxPending int) {
	for {
		select {
		case alert, ok := <-f.queue:
			if !ok {
				return
			}
			*pending = append(*pending, alert)
			if len(*pending) > maxPending {
				drop := len(*pending) - maxPending
				*pending = append((*pending)[:0], (*pending)[drop:]...)
				f.dropped.Add(uint64(drop))
			}
		default:
			return
		}
	}
}

func (f *BatchAlertSink) flush(pending *[]Alert) {
	if len(*pending) == 0 {
		return
	}
	now := time.Now()
	if openUntil := f.openUntil.Load(); openUntil != 0 && now.UnixNano() < openUntil {
		f.dropped.Add(uint64(len(*pending)))
		*pending = (*pending)[:0]
		return
	}
	if next := f.nextAttempt.Load(); next != 0 && now.UnixNano() < next {
		return
	}

	size := f.opts.BatchSize
	if size > len(*pending) {
		size = len(*pending)
	}
	batch := make([]Alert, size)
	copy(batch, (*pending)[:size])

	if err := f.send(batch); err != nil {
		f.failed.Add(uint64(len(batch)))
		failures := f.failures.Add(1)
		if f.opts.Logger != nil {
			f.opts.Logger.Warn("alert batch forward failed", "alerts", len(batch), "failures", failures, "error", err)
		}
		backoff := f.backoff(failures)
		f.nextAttempt.Store(now.Add(backoff).UnixNano())
		if int(failures) >= f.opts.BreakerThreshold {
			f.openUntil.Store(now.Add(f.opts.BreakerCooldown).UnixNano())
			f.dropped.Add(uint64(len(*pending)))
			*pending = (*pending)[:0]
		}
		return
	}

	f.failures.Store(0)
	f.nextAttempt.Store(0)
	f.openUntil.Store(0)
	f.sent.Add(uint64(len(batch)))
	*pending = append((*pending)[:0], (*pending)[size:]...)
}

// backoff doubles from BackoffBase (100ms by default) and saturates at
// MaxBackoff (5s by default), so a short console blip recovers quickly without
// ever turning into a long sleep.
func (f *BatchAlertSink) backoff(failures int32) time.Duration {
	if failures < 1 {
		failures = 1
	}
	backoff := f.opts.BackoffBase
	for attempt := int32(1); attempt < failures; attempt++ {
		if backoff >= f.opts.MaxBackoff {
			break
		}
		backoff *= 2
	}
	if backoff > f.opts.MaxBackoff {
		backoff = f.opts.MaxBackoff
	}
	return backoff
}

func (f *BatchAlertSink) send(batch []Alert) error {
	flows := make([]map[string]any, 0, len(batch))
	for _, alert := range batch {
		flows = append(flows, alert.Payload)
	}
	body, err := json.Marshal(map[string]any{"flows": flows})
	if err != nil {
		return fmt.Errorf("marshal alert batch: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, f.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build alert request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if f.opts.APIKey != "" {
		req.Header.Set("X-API-Key", f.opts.APIKey)
	}
	resp, err := f.opts.Client.Do(req)
	if err != nil {
		return fmt.Errorf("post alert batch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("alert receiver returned %s: %s", resp.Status, bytes.TrimSpace(snippet))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
