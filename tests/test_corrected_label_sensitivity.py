"""Tests for the corrected-label sensitivity policy and loader."""

from __future__ import annotations

import numpy as np
import pandas as pd

from scripts.corrected_label_sensitivity import corrected_role, load_corrected


def test_alias_mapping_preserves_the_frozen_policy():
    portscan = corrected_role("Portscan")
    assert portscan["role"] == "positive"
    assert portscan["mapped"] == "PortScan"

    slowloris = corrected_role("DoS Slowloris")
    assert slowloris["role"] == "positive"
    assert slowloris["mapped"] == "DoS slowloris"


def test_attempted_rows_are_excluded():
    for raw in (
        "Portscan - Attempted",
        "DoS Hulk - Attempted",
        "Infiltration - Attempted",
    ):
        decision = corrected_role(raw)
        assert decision["role"] == "excluded"
        assert "attempted" in decision["reason"]


def test_corrected_only_and_unknown_categories_are_excluded():
    assert corrected_role("Infiltration - Portscan")["role"] == "excluded"
    assert corrected_role("Botnet")["role"] == "excluded"
    assert corrected_role("not-a-known-label")["role"] == "excluded"
    assert corrected_role(None)["role"] == "excluded"


def test_loader_keeps_only_strict_policy_rows(tmp_path):
    frame = pd.DataFrame(
        {
            "Src IP": ["10.0.0.1"] * 5,
            "Dst IP": ["10.0.0.2"] * 5,
            "Src Port": [1000, 1001, 1002, 1003, 1004],
            "Dst Port": [80] * 5,
            "Protocol": [6] * 5,
            "Total Fwd Packet": [10, 20, 30, 40, 50],
            "Total Bwd packets": [5, 10, 15, 20, 25],
            "Total Length of Fwd Packet": [1000, 2000, 3000, 4000, 5000],
            "Total Length of Bwd Packet": [500, 1000, 1500, 2000, 2500],
            "Label": [
                "BENIGN",
                "Portscan",
                "Portscan - Attempted",
                "Botnet",
                "Infiltration - Portscan",
            ],
        }
    )
    frame.to_csv(tmp_path / "monday.csv", index=False)

    data = load_corrected(str(tmp_path))

    assert data["rows_read"] == 5
    assert data["rows_kept"] == 2
    assert data["truth"].tolist() == [0, 1]
    assert data["families"].tolist() == ["BENIGN", "PortScan"]
    assert data["prevalence"] == 0.5
    assert data["kept_label_counts"] == {"BENIGN": 1, "PortScan": 1}
    assert data["matrix"].shape == (2, 8)
    assert np.isfinite(data["matrix"]).all()
    assert data["portable_schema"]["count"] == 8
