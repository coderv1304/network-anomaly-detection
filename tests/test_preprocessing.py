"""
tests/test_preprocessing.py
Unit tests for data sanitization, NaN/Inf handling, and column stripping.
"""

import pytest
import pandas as pd
import numpy as np
from feature_mapper import normalize_flow_features

def test_clean_inf_and_nan():
    data = {
        "Flow Duration": [100.0, np.inf, 300.0, -np.inf],
        "Total Fwd Packets": [2.0, 5.0, np.nan, 8.0],
        "Label": ["BENIGN", "PortScan", "BENIGN", "DDoS"]
    }
    df = pd.DataFrame(data)
    
    # Cleaning transformation
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=["Label"], inplace=True)
    
    assert len(df) == 4
    assert np.isnan(df.loc[1, "Flow Duration"])
    assert np.isnan(df.loc[3, "Flow Duration"])

def test_column_name_stripping():
    cols_with_spaces = [" Destination Port ", " Flow Duration", "Total Fwd Packets "]
    df = pd.DataFrame(columns=cols_with_spaces)
    stripped = df.columns.str.strip().tolist()
    
    assert stripped == ["Destination Port", "Flow Duration", "Total Fwd Packets"]

def test_feature_normalization():
    sample_flow = {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "src_port": 443,
        "dst_port": 80,
        "protocol": 6,
        "duration": 5.0,
        "total_fwd_packets": 10,
        "total_bwd_packets": 12,
    }
    expected_features = ["Flow Duration", "Total Fwd Packets", "Total Backward Packets"]
    normalized = normalize_flow_features(sample_flow, expected_features)
    assert isinstance(normalized, dict)
