package flow

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
)

// SchemaVersion identifies the canonical packet-to-feature contract shared by
// offline training CSV generation (--mode=extract) and live sensor streaming.
const SchemaVersion = "netshield-flow-v1"

// FeatureCount is the number of canonical float64 features per flow.
const FeatureCount = 26

// FeatureNames is the immutable canonical feature order. Index positions are
// part of the wire contract: changing a name or an index requires a new
// SchemaVersion and a retrained model.
var FeatureNames = []string{
	"protocol",
	"duration_sec",
	"fwd_pkts",
	"bwd_pkts",
	"fwd_bytes",
	"bwd_bytes",
	"fwd_hdr_bytes",
	"bwd_hdr_bytes",
	"fin_cnt",
	"syn_cnt",
	"rst_cnt",
	"psh_cnt",
	"ack_cnt",
	"urg_cnt",
	"ece_cnt",
	"cwr_cnt",
	"flow_iat_mean",
	"flow_iat_std",
	"flow_iat_max",
	"pkt_len_mean",
	"pkt_len_std",
	"pkt_len_max",
	"bytes_per_sec",
	"pkts_per_sec",
	"fwd_bwd_pkt_ratio",
	"syn_ack_ratio",
}

// MetadataColumns are the non-feature columns written before FeatureNames in
// the extract CSV. start_ts is the flow's first packet in epoch microseconds.
var MetadataColumns = []string{
	"flow_id",
	"src_ip",
	"dst_ip",
	"src_port",
	"dst_port",
	"start_ts",
}

// SchemaSHA256 is the SHA-256 of the comma-joined feature names. Python tooling
// compares its own digest against this value at startup to prove that training
// and serving agree on the schema.
func SchemaSHA256() string {
	sum := sha256.Sum256([]byte(strings.Join(FeatureNames, ",")))
	return hex.EncodeToString(sum[:])
}

// CSVHeader returns the metadata columns followed by the canonical features.
func CSVHeader() []string {
	header := make([]string, 0, len(MetadataColumns)+FeatureCount)
	header = append(header, MetadataColumns...)
	header = append(header, FeatureNames...)
	return header
}

// CSVRow flattens a snapshot into the CSV layout declared by CSVHeader. Values
// use the shortest round-trippable decimal form so repeated runs over the same
// capture are byte-identical.
func (s *Snapshot) CSVRow() []string {
	values := s.FeatureValues()
	row := make([]string, 0, len(MetadataColumns)+FeatureCount)
	row = append(row,
		s.FlowID(),
		s.ForwardKey.SrcString(),
		s.ForwardKey.DstString(),
		strconv.FormatUint(uint64(s.ForwardKey.Src.Port), 10),
		strconv.FormatUint(uint64(s.ForwardKey.Dst.Port), 10),
		strconv.FormatInt(s.StartUS, 10),
	)
	for _, value := range values {
		row = append(row, strconv.FormatFloat(value, 'f', -1, 64))
	}
	return row
}

// sanitizeFeatures replaces every NaN or Infinity with 0.0 so a serialized
// feature row is always finite, even for degenerate captures.
func sanitizeFeatures(vec []float64) {
	for i, value := range vec {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			vec[i] = 0.0
		}
	}
}
