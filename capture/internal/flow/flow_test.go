package flow

import (
	"math"
	"net"
	"reflect"
	"testing"
	"time"

	"capture/internal/ingest"
)

func TestCanonicalSchemaContract(t *testing.T) {
	if SchemaVersion != "netshield-flow-v1" {
		t.Fatalf("unexpected schema version %q", SchemaVersion)
	}
	if FeatureCount != 26 {
		t.Fatalf("expected 26 canonical features, got %d", FeatureCount)
	}
	expected := []string{
		"protocol", "duration_sec", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
		"fwd_hdr_bytes", "bwd_hdr_bytes", "fin_cnt", "syn_cnt", "rst_cnt", "psh_cnt",
		"ack_cnt", "urg_cnt", "ece_cnt", "cwr_cnt", "flow_iat_mean", "flow_iat_std",
		"flow_iat_max", "pkt_len_mean", "pkt_len_std", "pkt_len_max", "bytes_per_sec",
		"pkts_per_sec", "fwd_bwd_pkt_ratio", "syn_ack_ratio",
	}
	if !reflect.DeepEqual(FeatureNames, expected) {
		t.Fatalf("canonical feature order changed:\n got %v\nwant %v", FeatureNames, expected)
	}
	seen := make(map[string]bool, len(FeatureNames))
	for _, name := range FeatureNames {
		if name == "" || seen[name] {
			t.Fatalf("feature name %q is empty or duplicated", name)
		}
		seen[name] = true
	}
	// Pinned digest: Go and Python compare this value at startup, so any
	// rename or reorder must be a deliberate schema bump.
	const wantDigest = "6ef22a3b0fdecdf3fb5119e5d7694c61ab9f920e52b993eb599fd924ab1de772"
	if got := SchemaSHA256(); got != wantDigest {
		t.Fatalf("schema digest changed: got %s want %s", got, wantDigest)
	}
	if len(ModelFeatureNames) != ModelFeatureCount || ModelFeatureCount != 24 {
		t.Fatalf("model input order must stay at 24 values, got %d/%d", len(ModelFeatureNames), ModelFeatureCount)
	}
}

func TestCSVHeaderFollowsSchema(t *testing.T) {
	header := CSVHeader()
	if len(header) != len(MetadataColumns)+FeatureCount {
		t.Fatalf("expected %d columns, got %d", len(MetadataColumns)+FeatureCount, len(header))
	}
	wantMetadata := []string{"flow_id", "src_ip", "dst_ip", "src_port", "dst_port", "start_ts"}
	if !reflect.DeepEqual(header[:len(wantMetadata)], wantMetadata) {
		t.Fatalf("unexpected metadata columns: %v", header[:len(wantMetadata)])
	}
	if !reflect.DeepEqual(header[len(wantMetadata):], FeatureNames) {
		t.Fatalf("feature columns do not follow FeatureNames: %v", header[len(wantMetadata):])
	}
}

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
	values := snapshot.FeatureValues()
	if values[9] != 3 || values[12] != 2 || values[8] != 1 {
		t.Fatalf("canonical flag features are wrong: syn=%v ack=%v fin=%v", values[9], values[12], values[8])
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
	if snapshot.ForwardKey.Src.IP != ip16("10.0.0.1") || snapshot.ForwardKey.Src.Port != 1234 {
		t.Fatalf("direction anchor was not flipped: %v", snapshot.ForwardKey)
	}
	if snapshot.FwdPkts != 1 || snapshot.BwdPkts != 2 {
		t.Fatalf("unexpected directional counts after flip: fwd=%d bwd=%d", snapshot.FwdPkts, snapshot.BwdPkts)
	}
	// The 100-byte mid-stream packet must have moved from forward to backward.
	if snapshot.FwdBytes != 60 || snapshot.BwdBytes != 140 {
		t.Fatalf("byte counters were not swapped: fwd=%d bwd=%d", snapshot.FwdBytes, snapshot.BwdBytes)
	}
	if snapshot.InitialKey.Src.IP != ip16("10.0.0.2") {
		t.Fatalf("initial directional key must be preserved: %v", snapshot.InitialKey)
	}
}

func TestSinglePacketFlowHasZeroStd(t *testing.T) {
	table, emitted := newTestTable()
	table.Process(packet("10.0.0.1", "10.0.0.2", 1234, 80, ingest.ProtoTCP, ingest.TCPFlagACK, 0, 40), emitted.collect)
	table.Flush(emitted.collect)
	if len(emitted.items) != 1 {
		t.Fatalf("expected one flow, got %d", len(emitted.items))
	}
	values := emitted.items[0].FeatureValues()
	if values[17] != 0 {
		t.Fatalf("single-packet flow_iat_std must be 0, got %v", values[17])
	}
	if values[20] != 0 {
		t.Fatalf("single-packet pkt_len_std must be 0, got %v", values[20])
	}
	for i, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			t.Fatalf("feature %s is not finite: %v", FeatureNames[i], value)
		}
	}
}

func TestFeatureValuesAreFinite(t *testing.T) {
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
	if values[0] != float64(ingest.ProtoTCP) {
		t.Fatalf("protocol feature must carry the IP protocol number, got %v", values[0])
	}
	if values[1] <= 0 {
		t.Fatalf("duration must have an epsilon floor, got %v", values[1])
	}
	if values[22] <= 0 || values[23] <= 0 {
		t.Fatalf("rate features should be positive: bytes/s=%v pkts/s=%v", values[22], values[23])
	}
	if model := emitted.items[0].ModelFeatureValues(); len(model) != ModelFeatureCount {
		t.Fatalf("model vector must stay %d wide, got %d", ModelFeatureCount, len(model))
	}
}

func TestSanitizeFeaturesRemovesNonFiniteValues(t *testing.T) {
	vec := []float64{1, math.NaN(), math.Inf(1), math.Inf(-1), 2}
	sanitizeFeatures(vec)
	for i, value := range vec {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			t.Fatalf("index %d is still non-finite: %v", i, value)
		}
	}
	if vec[0] != 1 || vec[4] != 2 {
		t.Fatalf("finite values were modified: %v", vec)
	}
}

func TestWelfordSampleStatistics(t *testing.T) {
	var single Welford
	single.Add(40)
	if single.Std() != 0 || single.Variance() != 0 {
		t.Fatalf("one observation must have zero variance, got std=%v var=%v", single.Std(), single.Variance())
	}

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
	// Sample (n-1) variance: 22400 / 2.
	expectedStd := math.Sqrt(11200)
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
	if snapshot.ForwardKey.Src.Port != 0 || snapshot.ForwardKey.Dst.Port != 0 {
		t.Fatalf("ICMP endpoints must use port 0: %v", snapshot.ForwardKey)
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
