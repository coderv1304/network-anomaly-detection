package flow

import (
	"testing"
	"time"

	"capture/internal/ingest"
)

func TestIdleTimeoutEviction(t *testing.T) {
	table := NewTable(15*time.Second, 120*time.Second)
	collected := &collector{}
	table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 0, 40), collected.collect)
	if table.Len() != 1 {
		t.Fatalf("expected one active flow, got %d", table.Len())
	}
	// A different flow at t=15s triggers the 1s sweep, which evicts the idle one.
	table.Process(packet("10.0.0.3", "10.0.0.4", 2222, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 15_000_000, 60), collected.collect)
	if len(collected.items) != 1 {
		t.Fatalf("expected idle flow to be evicted, got %d emissions", len(collected.items))
	}
	if collected.items[0].EndUS != 0 {
		t.Fatalf("idle flow end timestamp changed: %d", collected.items[0].EndUS)
	}
	if table.Len() != 1 {
		t.Fatalf("expected the new flow to remain, got %d", table.Len())
	}
}

func TestSameFlowAfterIdleTimeoutStartsNewFlow(t *testing.T) {
	table := NewTable(15*time.Second, 120*time.Second)
	collected := &collector{}
	table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 0, 40), collected.collect)
	table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 15_500_000, 40), collected.collect)
	if len(collected.items) != 1 {
		t.Fatalf("expected the stale flow to be emitted before reuse, got %d", len(collected.items))
	}
	if table.Len() != 1 {
		t.Fatalf("expected a fresh flow, got %d", table.Len())
	}
	table.Flush(collected.collect)
	if len(collected.items) != 2 {
		t.Fatalf("expected two flow instances, got %d", len(collected.items))
	}
}

func TestActiveTimeoutEviction(t *testing.T) {
	table := NewTable(15*time.Second, 120*time.Second)
	collected := &collector{}
	for second := int64(0); second <= 110; second += 10 {
		table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, second*1_000_000, 40), collected.collect)
	}
	if len(collected.items) != 0 {
		t.Fatalf("flow must remain active before 120s, got %d emissions", len(collected.items))
	}
	// The packet exactly at the active boundary is attributed to a new flow.
	table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 120_000_000, 40), collected.collect)
	if len(collected.items) != 1 {
		t.Fatalf("expected active timeout eviction at 120s, got %d", len(collected.items))
	}
	if collected.items[0].StartUS != 0 || collected.items[0].EndUS != 110_000_000 {
		t.Fatalf("unexpected active flow bounds: %d..%d", collected.items[0].StartUS, collected.items[0].EndUS)
	}
	table.Flush(collected.collect)
	if len(collected.items) != 2 {
		t.Fatalf("expected two flow instances after active timeout, got %d", len(collected.items))
	}
}

func TestSweepIsDeterministic(t *testing.T) {
	table := NewTable(15*time.Second, 120*time.Second)
	collected := &collector{}
	table.Process(packet("10.0.0.1", "10.0.0.2", 1111, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 0, 40), collected.collect)
	// Less than one virtual second should not trigger a sweep.
	table.Process(packet("10.0.0.3", "10.0.0.4", 2222, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 999_999, 40), collected.collect)
	if len(collected.items) != 0 {
		t.Fatalf("sweep ran before the 1s boundary: %d", len(collected.items))
	}
	table.Process(packet("10.0.0.5", "10.0.0.6", 3333, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 1_000_000, 40), collected.collect)
	if len(collected.items) != 0 {
		t.Fatalf("young flows must not be evicted by a sweep: %d", len(collected.items))
	}
}
