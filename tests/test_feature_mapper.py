"""
tests/test_feature_mapper.py

Unit tests for feature_mapper.py ensuring snake_case normalization
and mapping to model-expected CIC-IDS-2017 feature names.
"""

import pytest
from feature_mapper import _auto_normalize, normalize_flow_features, FEATURE_NAME_OVERRIDES

def test_auto_normalize_common_abbreviations():
    assert _auto_normalize("tot_fwd_pkts") == "Total Fwd Packets"
    assert _auto_normalize("flow_duration") == "Flow Duration"
    assert _auto_normalize("pkt_len_mean") == "Packet Length Mean"

def test_normalize_flow_features_with_expected():
    expected = ["Flow Duration", "Total Fwd Packets", "Destination Port"]
    raw_flow = {
        "flow_duration": 1500,
        "tot_fwd_pkts": 8,
        "Destination Port": 443,
        "unrecognized_strange_key": 999
    }
    normalized = normalize_flow_features(raw_flow, expected)

    assert normalized.get("Flow Duration") == 1500
    assert normalized.get("Total Fwd Packets") == 8
    assert normalized.get("Destination Port") == 443
    assert "unrecognized_strange_key" not in normalized
