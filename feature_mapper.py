"""
feature_mapper.py

The live capture tool (pyflowmeter) and the PCAP dissector emit feature names
in snake_case (e.g. ``flow_duration``, ``tot_fwd_pkts``), while the model was
trained on the original CIC-IDS-2017 CSV column names, which are Title Case
With Spaces (e.g. ``Flow Duration``, ``Total Fwd Packets``).

This module bridges the two. The override table below is deliberately explicit:
automatic snake_case expansion is useful for unknown tools, but it cannot know
that ``fwd_iat_tot`` means ``Fwd IAT Total`` or that ``pkt_len_max`` means
``Max Packet Length``. Leaving those to the heuristic silently produced a
mostly empty feature row.

Run ``GET /api/unmapped-features`` to see any raw names that still fail to map.
"""

import re

# Known abbreviation expansions used by CICFlowMeter-style tools. This is only
# a fallback for names that are not in FEATURE_NAME_OVERRIDES.
_ABBREVIATIONS = {
    "tot": "total",
    "pkt": "packet",
    "pkts": "packets",
    "len": "length",
    "std": "std",
    "iat": "iat",
    "seg": "segment",
    "byts": "bytes",
    "flg": "flags",
    "cnt": "count",
    "avg": "mean",
}

# Explicit pyflowmeter / CICFlowMeter snake_case -> CIC-IDS-2017 column names.
# Every feature in the 80-feature serving schema must appear here if the raw
# name is not already identical to the expected column name.
FEATURE_NAME_OVERRIDES = {
    # Basic flow fields
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "protocol": "Protocol",
    "flow_duration": "Flow Duration",
    # Packet counts and byte totals
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    # Packet length statistics
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    # Rates
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    # Inter-arrival times
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    # TCP flags
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwe_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    # Header lengths and derived sizes
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "pkt_size_avg": "Average Packet Size",
    # Ratios
    "down_up_ratio": "Down/Up Ratio",
    # Bulk statistics
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    # Subflows
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    # TCP window and payload fields
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    # Active / idle
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}

# Expected columns that are derived from another mapped column. The source CSV
# contains two identical "Fwd Header Length" headers; pandas keeps the second
# as "Fwd Header Length.1". pyflowmeter emits the value only once.
DERIVED_FEATURES = {
    "Fwd Header Length.1": "Fwd Header Length",
}

# Raw keys that are identifiers or parser metadata, never model features.
IGNORED_RAW_KEYS = {
    "src_ip",
    "dst_ip",
    "src_mac",
    "dst_mac",
    "timestamp",
    "flow_id",
    "Packet Dissector",
}

# Populated at runtime; inspect via GET /api/unmapped-features
UNMAPPED_LOG = set()


def _auto_normalize(raw_name: str) -> str:
    """Best-effort snake_case -> 'Title Case With Spaces' conversion."""
    name = raw_name.strip()
    name = re.sub(r"[/_]+", " ", name)
    words = []
    for word in name.split():
        lower = word.lower()
        expanded = _ABBREVIATIONS.get(lower, lower)
        words.append(expanded.capitalize())
    return " ".join(words)


def normalize_flow_features(raw_flow: dict, expected_features: list) -> dict:
    """Map a raw flow dict's keys onto the model's expected feature names.

    Unmatched raw keys are dropped and logged to ``UNMAPPED_LOG``. Expected
    features that never get a value are left absent so the caller can decide
    whether to impute them (preferred) or fill them with zero (legacy path).
    """
    expected_set = set(expected_features)
    result = {}

    for raw_key, value in raw_flow.items():
        if raw_key in IGNORED_RAW_KEYS:
            continue
        if raw_key in expected_set:
            result[raw_key] = value
            continue
        if raw_key in FEATURE_NAME_OVERRIDES:
            mapped = FEATURE_NAME_OVERRIDES[raw_key]
            if mapped in expected_set:
                result[mapped] = value
            else:
                UNMAPPED_LOG.add(raw_key)
            continue

        guess = _auto_normalize(raw_key)
        if guess in expected_set:
            result[guess] = value
        else:
            UNMAPPED_LOG.add(raw_key)

    for derived, source in DERIVED_FEATURES.items():
        if derived in expected_set and derived not in result and source in result:
            result[derived] = result[source]

    return result
