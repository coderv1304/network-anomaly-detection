package state

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryWindowStoreSlidingWindow(t *testing.T) {
	acc := NewMemoryWindowStore(300 * time.Second)
	ctx := context.Background()

	first, err := acc.Record(ctx, Event{SourceIP: "10.0.0.1", TimestampUS: 0, Risk: 50, FlowID: "a"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Count != 1 || first.RiskSum != 50 || first.Score != 50 {
		t.Fatalf("unexpected first window: %+v", first)
	}
	second, _ := acc.Record(ctx, Event{SourceIP: "10.0.0.1", TimestampUS: 100_000_000, Risk: 50, FlowID: "b"})
	if second.Count != 2 || second.Score != 100 {
		t.Fatalf("unexpected second window: %+v", second)
	}
	third, _ := acc.Record(ctx, Event{SourceIP: "10.0.0.1", TimestampUS: 301_000_000, Risk: 50, FlowID: "c"})
	if third.Count != 2 {
		t.Fatalf("expected t=0 event to be pruned, got %+v", third)
	}
	if third.Score != 100 {
		t.Fatalf("score must be capped at 100, got %v", third.Score)
	}
}

func TestMemoryWindowStoreIsShardedAndConcurrent(t *testing.T) {
	acc := NewMemoryWindowStore(time.Minute)
	ctx := context.Background()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				_, _ = acc.Record(ctx, Event{
					SourceIP:    fmt.Sprintf("10.0.%d.%d", id, j%10),
					TimestampUS: int64(j) * 1000,
					Risk:        1,
					FlowID:      fmt.Sprintf("%d-%d", id, j),
				})
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

func TestBatchAlertSinkBatchesAndAuthenticates(t *testing.T) {
	received := make(chan []map[string]any, 4)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Flows []map[string]any `json:"flows"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		received <- payload.Flows
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	forwarder, err := NewBatchAlertSink(BatchAlertSinkOptions{
		URL:           server.URL,
		APIKey:        "secret",
		BatchSize:     2,
		FlushInterval: 20 * time.Millisecond,
		MaxBackoff:    50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.Start(context.Background())
	defer forwarder.Close()

	for i := 0; i < 2; i++ {
		if !forwarder.Enqueue(Alert{FlowID: fmt.Sprintf("f%d", i), Payload: map[string]any{"flow_id": fmt.Sprintf("f%d", i)}}) {
			t.Fatalf("enqueue %d failed", i)
		}
	}
	select {
	case flows := <-received:
		if len(flows) != 2 {
			t.Fatalf("expected a batch of 2, got %d", len(flows))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for alert batch")
	}
}

func TestBatchAlertSinkRetriesWithBackoff(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) <= 2 {
			http.Error(w, "try later", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	forwarder, err := NewBatchAlertSink(BatchAlertSinkOptions{
		URL:              server.URL,
		BatchSize:        1,
		FlushInterval:    10 * time.Millisecond,
		MaxBackoff:       40 * time.Millisecond,
		BreakerThreshold: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.Start(context.Background())
	defer forwarder.Close()
	forwarder.Enqueue(Alert{FlowID: "retry", Payload: map[string]any{"flow_id": "retry"}})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if forwarder.Sent() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if forwarder.Sent() != 1 {
		t.Fatalf("alert was not delivered after retries: sent=%d failed=%d", forwarder.Sent(), forwarder.Failed())
	}
	if forwarder.Failed() != 2 {
		t.Fatalf("expected two failed attempts, got %d", forwarder.Failed())
	}
}

func TestBatchAlertSinkCircuitBreakerDropsDuringCooldown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer server.Close()

	forwarder, err := NewBatchAlertSink(BatchAlertSinkOptions{
		URL:              server.URL,
		BatchSize:        1,
		FlushInterval:    10 * time.Millisecond,
		MaxBackoff:       10 * time.Millisecond,
		BreakerThreshold: 2,
		BreakerCooldown:  200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	forwarder.Start(context.Background())
	defer forwarder.Close()
	forwarder.Enqueue(Alert{FlowID: "breaker", Payload: map[string]any{"flow_id": "breaker"}})

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if forwarder.Failed() >= 2 && forwarder.Dropped() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if forwarder.Failed() < 2 {
		t.Fatalf("expected at least two failed attempts, got %d", forwarder.Failed())
	}
	if forwarder.Dropped() == 0 {
		t.Fatal("open circuit should drop queued alerts")
	}
}
