package flow

import (
	"encoding/json"
	"math"
	"strconv"

	"capture/internal/ingest"
)

// RatioEpsilon guards every division that could otherwise produce NaN or Inf.
const RatioEpsilon = 1e-6

// Snapshot is an immutable flow record. It is safe to send across goroutines.
type Snapshot struct {
	Key        ingest.FlowKey
	InitialKey ingest.FlowKey
	// ForwardKey is the TCP initiator (or first sender for non-TCP) after
	// any mid-stream direction flip.
	ForwardKey ingest.FlowKey

	StartUS int64
	EndUS   int64

	FwdPkts     uint64
	BwdPkts     uint64
	FwdBytes    uint64
	BwdBytes    uint64
	FwdHdrBytes uint64
	BwdHdrBytes uint64

	FinCnt uint64
	SynCnt uint64
	RstCnt uint64
	PshCnt uint64
	AckCnt uint64
	UrgCnt uint64
	EceCnt uint64
	CwrCnt uint64

	FwdPSHCnt uint64
	BwdPSHCnt uint64
	FwdURGCnt uint64
	BwdURGCnt uint64

	FlowIATTotalUS int64
	FlowIAT        Summary
	FwdIAT         Summary
	BwdIAT         Summary
	FwdLen         Summary
	BwdLen         Summary
	AllLen         Summary

	InitFwdWin     uint16
	InitBwdWin     uint16
	FwdPayloadPkts uint64

	SawFwdSYN bool
	FinFwd    bool
	FinBwd    bool
}

// DurationSeconds returns the observed flow duration with an epsilon floor.
func (s *Snapshot) DurationSeconds() float64 {
	return math.Max(float64(s.EndUS-s.StartUS)/float64(microsPerSecond), RatioEpsilon)
}

// FeatureValues returns the canonical 26 features in FeatureNames order. Time
// statistics are microseconds, lengths are bytes, and every value is finite:
// malformed ratios fall back to zero.
func (s *Snapshot) FeatureValues() [FeatureCount]float64 {
	var out [FeatureCount]float64
	duration := s.DurationSeconds()
	totalPackets := s.FwdPkts + s.BwdPkts
	totalBytes := s.FwdBytes + s.BwdBytes

	out[0] = float64(s.ForwardKey.Proto)
	out[1] = duration
	out[2] = float64(s.FwdPkts)
	out[3] = float64(s.BwdPkts)
	out[4] = float64(s.FwdBytes)
	out[5] = float64(s.BwdBytes)
	out[6] = float64(s.FwdHdrBytes)
	out[7] = float64(s.BwdHdrBytes)
	out[8] = float64(s.FinCnt)
	out[9] = float64(s.SynCnt)
	out[10] = float64(s.RstCnt)
	out[11] = float64(s.PshCnt)
	out[12] = float64(s.AckCnt)
	out[13] = float64(s.UrgCnt)
	out[14] = float64(s.EceCnt)
	out[15] = float64(s.CwrCnt)
	out[16] = finite(s.FlowIAT.Mean)
	out[17] = finite(s.FlowIAT.Std)
	out[18] = finite(s.FlowIAT.Max)
	out[19] = finite(s.AllLen.Mean)
	out[20] = finite(s.AllLen.Std)
	out[21] = finite(s.AllLen.Max)
	out[22] = safeDiv(float64(totalBytes), duration)
	out[23] = safeDiv(float64(totalPackets), duration)
	out[24] = safeDiv(float64(s.FwdPkts), float64(maxUint(s.BwdPkts, 1)))
	out[25] = safeDiv(float64(s.SynCnt), float64(maxUint(s.AckCnt, 1)))

	sanitizeFeatures(out[:])
	return out
}

// FeatureMap returns the canonical features keyed by their schema names.
func (s *Snapshot) FeatureMap() map[string]float64 {
	values := s.FeatureValues()
	out := make(map[string]float64, FeatureCount)
	for i, name := range FeatureNames {
		out[name] = values[i]
	}
	return out
}

// FlowID is a stable identity for this flow instance.
func (s *Snapshot) FlowID() string {
	return s.Key.Hex() + "-" + strconv.FormatInt(s.StartUS, 10)
}

// IsElephant identifies a high-volume established flow. The inference queue
// sheds these first when it is saturated.
func (s *Snapshot) IsElephant() bool {
	return s.SynCnt == 0 && s.FinCnt == 0 && (s.FwdBytes+s.BwdBytes) > 1_000_000
}

// CICMap renders the snapshot with the snake_case names that
// feature_mapper.normalize_flow_features understands. Unknown keys are kept
// out on purpose so the Flask ingest path does not log unmapped features.
func (s *Snapshot) CICMap() map[string]any {
	durationUS := float64(maxInt64(s.EndUS-s.StartUS, 0))
	durationSeconds := durationUS / float64(microsPerSecond)
	totalPackets := s.FwdPkts + s.BwdPkts
	totalBytes := s.FwdBytes + s.BwdBytes

	out := map[string]any{
		"flow_id":           s.FlowID(),
		"src_ip":            s.ForwardKey.SrcString(),
		"dst_ip":            s.ForwardKey.DstString(),
		"src_port":          int(s.ForwardKey.Src.Port),
		"dst_port":          int(s.ForwardKey.Dst.Port),
		"protocol":          int(s.ForwardKey.Proto),
		"timestamp":         float64(s.StartUS) / float64(microsPerSecond),
		"flow_duration":     durationUS,
		"tot_fwd_pkts":      int(s.FwdPkts),
		"tot_bwd_pkts":      int(s.BwdPkts),
		"totlen_fwd_pkts":   int(s.FwdBytes),
		"totlen_bwd_pkts":   int(s.BwdBytes),
		"fwd_header_len":    int(s.FwdHdrBytes),
		"bwd_header_len":    int(s.BwdHdrBytes),
		"fwd_pkt_len_mean":  finite(s.FwdLen.Mean),
		"fwd_pkt_len_std":   finite(s.FwdLen.Std),
		"fwd_pkt_len_max":   finite(s.FwdLen.Max),
		"fwd_pkt_len_min":   finite(s.FwdLen.Min),
		"bwd_pkt_len_mean":  finite(s.BwdLen.Mean),
		"bwd_pkt_len_std":   finite(s.BwdLen.Std),
		"bwd_pkt_len_max":   finite(s.BwdLen.Max),
		"bwd_pkt_len_min":   finite(s.BwdLen.Min),
		"pkt_len_mean":      finite(s.AllLen.Mean),
		"pkt_len_std":       finite(s.AllLen.Std),
		"pkt_len_max":       finite(s.AllLen.Max),
		"pkt_len_min":       finite(s.AllLen.Min),
		"pkt_len_var":       finite(s.AllLen.Std * s.AllLen.Std),
		"flow_iat_total":    float64(s.FlowIATTotalUS),
		"flow_iat_mean":     finite(s.FlowIAT.Mean),
		"flow_iat_std":      finite(s.FlowIAT.Std),
		"flow_iat_max":      finite(s.FlowIAT.Max),
		"flow_iat_min":      finite(s.FlowIAT.Min),
		"fwd_iat_mean":      finite(s.FwdIAT.Mean),
		"fwd_iat_std":       finite(s.FwdIAT.Std),
		"fwd_iat_max":       finite(s.FwdIAT.Max),
		"fwd_iat_min":       finite(s.FwdIAT.Min),
		"bwd_iat_mean":      finite(s.BwdIAT.Mean),
		"bwd_iat_std":       finite(s.BwdIAT.Std),
		"bwd_iat_max":       finite(s.BwdIAT.Max),
		"bwd_iat_min":       finite(s.BwdIAT.Min),
		"flow_byts_s":       safeDiv(float64(totalBytes), durationSeconds),
		"flow_pkts_s":       safeDiv(float64(totalPackets), durationSeconds),
		"fwd_pkts_s":        safeDiv(float64(s.FwdPkts), durationSeconds),
		"bwd_pkts_s":        safeDiv(float64(s.BwdPkts), durationSeconds),
		"fin_flag_cnt":      int(s.FinCnt),
		"syn_flag_cnt":      int(s.SynCnt),
		"rst_flag_cnt":      int(s.RstCnt),
		"psh_flag_cnt":      int(s.PshCnt),
		"ack_flag_cnt":      int(s.AckCnt),
		"urg_flag_cnt":      int(s.UrgCnt),
		"ece_flag_cnt":      int(s.EceCnt),
		"cwe_flag_count":    int(s.CwrCnt),
		"fwd_psh_flags":     int(s.FwdPSHCnt),
		"bwd_psh_flags":     int(s.BwdPSHCnt),
		"fwd_urg_flags":     int(s.FwdURGCnt),
		"bwd_urg_flags":     int(s.BwdURGCnt),
		"init_fwd_win_byts": int(s.InitFwdWin),
		"init_bwd_win_byts": int(s.InitBwdWin),
		"fwd_act_data_pkts": int(s.FwdPayloadPkts),
		"fwd_seg_size_avg":  finite(s.FwdLen.Mean),
		"bwd_seg_size_avg":  finite(s.BwdLen.Mean),
		"pkt_size_avg":      safeDiv(float64(totalBytes), float64(maxUint(totalPackets, 1))),
		"down_up_ratio":     safeDiv(float64(s.BwdPkts), float64(maxUint(s.FwdPkts, 1))),
		"subflow_fwd_pkts":  int(s.FwdPkts),
		"subflow_fwd_byts":  int(s.FwdBytes),
		"subflow_bwd_pkts":  int(s.BwdPkts),
		"subflow_bwd_byts":  int(s.BwdBytes),
		"active_mean":       finite(s.FlowIAT.Mean),
		"active_std":        finite(s.FlowIAT.Std),
		"active_max":        finite(s.FlowIAT.Max),
		"active_min":        finite(s.FlowIAT.Min),
		"idle_mean":         0.0,
		"idle_std":          0.0,
		"idle_max":          0.0,
		"idle_min":          0.0,
	}
	return out
}

// MarshalJSON makes the snapshot serializable without exposing mutable state.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.CICMap())
}

func safeDiv(numerator, denominator float64) float64 {
	if denominator == 0 || math.IsNaN(denominator) || math.IsInf(denominator, 0) {
		return 0
	}
	result := numerator / denominator
	return finite(result)
}

func maxUint(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
