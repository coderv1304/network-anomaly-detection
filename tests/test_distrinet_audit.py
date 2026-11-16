"""Tests for the DistriNet-corrected CIC-IDS-2017 audit helper."""

from __future__ import annotations

import pandas as pd

from scripts.audit_distrinet_cicids2017 import (
    CORRECTED_PORTABLE_MAP,
    CORRECTED_TIER_A_MAP,
    audit,
)
from scripts.external_dataset_audit import TIER_A_FEATURES
from training.portable_features import PORTABLE_INPUT_COLUMNS


def test_corrected_mappings_cover_the_frozen_schemas():
    assert set(CORRECTED_TIER_A_MAP) == set(TIER_A_FEATURES)
    assert set(CORRECTED_PORTABLE_MAP) == set(PORTABLE_INPUT_COLUMNS)


def test_audit_reads_a_synthetic_corrected_file(tmp_path):
    frame = pd.DataFrame(
        {
            "Flow Duration": [1.0, 2.0],
            "Total Fwd Packet": [1, 2],
            "Total Bwd packets": [0, 3],
            "Total Length of Fwd Packet": [10, 20],
            "Total Length of Bwd Packet": [0, 30],
            "Flow Packets/s": [1.0, 2.0],
            "Flow Bytes/s": [10.0, 20.0],
            "Packet Length Mean": [10.0, 10.0],
            "Packet Length Max": [10, 10],
            "SYN Flag Count": [0, 1],
            "FIN Flag Count": [1, 1],
            "RST Flag Count": [0, 0],
            "Label": ["BENIGN", "Portscan"],
            "Attempted Category": ["", "Portscan"],
        }
    )
    frame.to_csv(tmp_path / "monday.csv", index=False)
    payload = audit(str(tmp_path), None, None)
    assert payload["rows"] == 2
    assert payload["tier_a"]["available"] == 12
    assert payload["portable_inputs"]["available"] == 4
    assert payload["label_counts"] == {"BENIGN": 1, "Portscan": 1}
    assert payload["attempted_category_counts"] == {"Portscan": 1}
    assert payload["files"]["monday.csv"]["rows"] == 2
