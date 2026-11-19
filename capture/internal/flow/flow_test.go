package flow

import (
	"math"
	"net"
	"testing"
	"time"

	"capture/internal/ingest"
)

func TestExactTCPFlagCounts(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 0, 60), emitted.collect)
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 1_000_000, 60), emitted.collect)
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN|ingest.TCPFlagACK, 2_000_000, 60), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagACK, 3_000_000, 40), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagFIN, 4_000_000, 40), emitted.collect)
	table.Flush(emitted.collect)

	if len(emitted.items) != 1 {
		t.Fatalf("expected one flow, got %d", len(emitted.items))
	}
	snapshot := emitted.items[0]
	if snapshot.SynCnt != 3 || snapshot.AckCnt != 2 || snapshot.FinCnt != 1 {
		t.Fatalf("unexpected flag counts: syn=%d ack=%d fin=%d", snapshot.SynCnt, snapshot.AckCnt, snapshot.FinCnt)
	}
	if snapshot.FwdPkts != 3 || snapshot.BwdPkts != 2 {
		t.Fatalf("unexpected directional packet counts: fwd=%d bwd=%d", snapshot.FwdPkts, snapshot.BwdPkts)
	}
	if snapshot.FwdBytes != 180 || snapshot.BwdBytes != 80 {
		t.Fatalf("unexpected byte counts: fwd=%d bwd=%d", snapshot.FwdBytes, snapshot.BwdBytes)
	}
}

func TestFinHandshakeFlushesImmediately(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 0, 60), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagSYN|ingest.TCPFlagACK, 1_000_000, 60), emitted.collect)
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 2_000_000, 40), emitted.collect)
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagFIN|ingest.TCPFlagACK, 3_000_000, 40), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagFIN|ingest.TCPFlagACK, 4_000_000, 40), emitted.collect)

	if len(emitted.items) != 1 {
		t.Fatalf("completed FIN handshake should flush exactly one flow, got %d", len(emitted.items))
	}
	if table.Len() != 0 {
		t.Fatalf("table should be empty after FIN flush, got %d", table.Len())
	}
	if emitted.items[0].FinCnt != 2 {
		t.Fatalf("expected two FINs, got %d", emitted.items[0].FinCnt)
	}
}

func TestRSTFlushesImmediately(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 0, 60), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagRST|ingest.TCPFlagACK, 1_000_000, 40), emitted.collect)

	if len(emitted.items) != 1 {
		t.Fatalf("RST should flush exactly one flow, got %d", len(emitted.items))
	}
	if emitted.items[0].RstCnt != 1 {
		t.Fatalf("expected one RST, got %d", emitted.items[0].RstCnt)
	}
}

func TestReverseSYNFlipsDirectionAnchor(t *testing.T) {
	table, emitted := newTestTable()
	// Mid-stream capture starts with the responder's data packet.
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagACK|ingest.TCPFlagPSH, 0, 100), emitted.collect)
	// The true initiator's reverse SYN arrives next.
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagSYN, 1_000_000, 60), emitted.collect)
	table.Process(packet("10.0.0.2", "10.0.0.1", 80, 1234, ingest.ProtoTCP, ingest.TCPFlagACK, 2_000_000, 40), emitted.collect)
	table.Flush(emitted.collect)

	if len(emitted.items) != 1 {
		t.Fatalf("expected one flow, got %d", len(emitted.items))
	}
	snapshot := emitted.items[0]
	if snapshot.ForwardKey.SrcIP != ip16("10.0.0.1") || snapshot.ForwardKey.SrcPort != 1234 {
		t.Fatalf("direction anchor was not flipped: %v", snapshot.ForwardKey)
	}
	if snapshot.FwdPkts != 1 || snapshot.BwdPkts != 2 {
		t.Fatalf("unexpected directional counts after flip: fwd=%d bwd=%d", snapshot.FwdPkts, snapshot.BwdPkts)
	}
	if snapshot.InitialKey.SrcIP != ip16("10.0.0.2") {
		t.Fatalf("initial directional key must be preserved: %v", snapshot.InitialKey)
	}
}

func TestFeatureVectorIsFinite(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("2001:db8::1", "2001:db8::2", 4444, 443, ingest.ProtoTCP, ingest.TCPFlagPSH|ingest.TCPFlagACK, 0, 74, true), emitted.collect)
	table.Flush(emitted.collect)
	if len(emitted.items) != 1 {
		t.Fatalf("expected one flow, got %d", len(emitted.items))
	}
	values := emitted.items[0].FeatureValues()
	for i, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			t.Fatalf("feature %s is not finite: %v", FeatureNames[i], value)
		}
	}
	if values[0] <= 0 {
		t.Fatalf("duration must have an epsilon floor, got %v", values[0])
	}
	if values[16] <= 0 || values[17] <= 0 {
		t.Fatalf("rate features should be positive: bytes/s=%v pkts/s=%v", values[16], values[17])
	}
}

func TestWelfordPopulationStatistics(t *testing.T) {
	var w Welford
	for _, value := range []float64{40, 80, 240} {
		w.Add(value)
	}
	if w.Count != 3 {
		t.Fatalf("expected count 3, got %d", w.Count)
	}
	if math.Abs(w.Mean-120) > 1e-9 {
		t.Fatalf("expected mean 120, got %v", w.Mean)
	}
	expectedStd := math.Sqrt((6400.0 + 1600.0 + 14400.0) / 3.0)
	if math.Abs(w.Std()-expectedStd) > 1e-9 {
		t.Fatalf("expected std %v, got %v", expectedStd, w.Std())
	}
}

func TestNonTCPFlowsHaveNoTCPFlags(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("10.0.0.1", "10.0.0.2", 0, 0, ingest.ProtoICMP, 0, 0, 84), emitted.collect)
	table.Flush(emitted.collect)
	if len(emitted.items) != 1 {
		t.Fatalf("expected one ICMP flow, got %d", len(emitted.items))
	}
	snapshot := emitted.items[0]
	if snapshot.SynCnt != 0 || snapshot.AckCnt != 0 || snapshot.FinCnt != 0 {
		t.Fatalf("ICMP flow must not have TCP flags: %+v", snapshot)
	}
	if snapshot.FwdPkts != 1 {
		t.Fatalf("expected one forward packet, got %d", snapshot.FwdPkts)
	}
}

type collector struct {
	items []Snapshot
}

func (c *collector) collect(snapshot Snapshot) {
	c.items = append(c.items, snapshot)
}

func newTestTable() (*Table, *collector) {
	return NewTable(time.Hour, time.Hour), &collector{}
}

func packet(src, dst string, sport, dport uint16, proto uint8, flags uint8, timestampUS int64, length int, ipv6 ...bool) *ingest.Packet {
	isIPv6 := len(ipv6) > 0 && ipv6[0]
	return &ingest.Packet{
		TimestampUS: timestampUS,
		SrcIP:       ip16(src),
		DstIP:       ip16(dst),
		SrcPort:     sport,
		DstPort:     dport,
		Proto:       proto,
		IsIPv6:      isIPv6,
		TCPFlags:    flags,
		Length:      length,
		HeaderLen:   20,
	}
}

func ip16(value string) [16]byte {
	var out [16]byte
	ip := net.ParseIP(value)
	if ip == nil {
		panic("bad test IP " + value)
	}
	if v4 := ip.To4(); v4 != nil {
		copy(out[:4], v4)
		return out
	}
	copy(out[:], ip.To16())
	return out
}
