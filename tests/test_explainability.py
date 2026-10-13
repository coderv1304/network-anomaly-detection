"""
tests/test_explainability.py

Unit tests for feature taxonomy and domain grouping.
"""

import pytest
from training.explainability_shap import identify_feature_group, FEATURE_GROUPS

def test_identify_feature_group_timing():
    assert identify_feature_group("Flow Duration") == "Timing & Inter-Arrival"
    assert identify_feature_group("Flow IAT Mean") == "Timing & Inter-Arrival"

def test_identify_feature_group_flags():
    assert identify_feature_group("SYN Flag Count") == "TCP Flags"
    assert identify_feature_group("FIN Flag Count") == "TCP Flags"

def test_identify_feature_group_packets():
    assert identify_feature_group("Total Fwd Packets") == "Packet Counts & Headers"
    assert identify_feature_group("Packet Length Mean") == "Packet Lengths & Sizes"

def test_identify_feature_group_unknown():
    assert identify_feature_group("Nonexistent_Feature") == "Other / Derived"
