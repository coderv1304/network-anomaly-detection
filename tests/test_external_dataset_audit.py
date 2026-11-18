"""Hand-computed tests for the external dataset audit.

These tests use synthetic frames and temporary directories. They never read the
production downloads, the score caches, or the serving artifact.
"""

from __future__ import annotations

import pandas as pd

from scripts.external_dataset_audit import (
    audit_cic,
    audit_unsw,
    cic2018_family,
    cic2018_label_class,
    day_partitions,
    group_partition,
    normalize_label,
    stable_bucket,
    unsw_label_class,
)
from scripts.p2b_protocol_analysis import coverage_gate, family_day_matrix


def test_normalize_label_handles_en_dash_and_whitespace():
    assert normalize_label("  Web Attack \u2013 XSS  ") == "Web Attack - XSS"
    assert normalize_label("DoS   Hulk") == "DoS Hulk"
    assert normalize_label(float("nan")) == ""


def test_unsw_label_class_maps_only_dos_and_reconnaissance_to_positive():
    assert unsw_label_class("DoS") == "positive"
    assert unsw_label_class("Reconnaissance") == "positive"
    assert unsw_label_class("Normal") == "negative"
    assert unsw_label_class("Generic") == "excluded"
    assert unsw_label_class("Exploits") == "excluded"


def test_cic2018_label_class_maps_volumetric_and_scanning_labels():
    assert cic2018_label_class("Benign") == "negative"
    assert cic2018_label_class("DDoS") == "positive"
    assert cic2018_label_class("DDoS attacks-LOIT") == "positive"
    assert cic2018_label_class("DoS") == "positive"
    assert cic2018_label_class("DoS attacks-Hulk") == "positive"
    assert cic2018_label_class("PortScan") == "positive"
    assert cic2018_label_class("FTP-BruteForce") == "excluded"
    assert cic2018_label_class("SSH-Bruteforce") == "excluded"
    assert cic2018_label_class("Web Attack - XSS") == "excluded"
    assert cic2018_label_class("Dosomething") == "excluded"


def test_stable_bucket_is_deterministic_and_in_range():
    assert stable_bucket("flow-1") == stable_bucket("flow-1")
    assert 0 <= stable_bucket("flow-1") < 100
    assert group_partition("flow-1") in {"train", "validation"}
    assert group_partition("flow-1") == group_partition("flow-1")


def test_day_partitions_requires_three_days():
    assert day_partitions(["2018-02-14"]) is None
    assert day_partitions(["2018-02-14", "2018-02-15"]) is None


def test_day_partitions_assigns_one_day_to_each_partition_for_three_days():
    split = day_partitions(["2018-02-16", "2018-02-14", "2018-02-15"])

    assert split == {
        "2018-02-14": "train",
        "2018-02-15": "validation",
        "2018-02-16": "test",
    }


def test_day_partitions_keeps_all_partitions_non_empty_for_eight_days():
    days = [f"2018-02-{day:02d}" for day in range(14, 22)]
    split = day_partitions(days)

    assert split is not None
    partitions = set(split.values())
    assert partitions == {"train", "validation", "test"}
    assert len(split) == len(days)


def test_coverage_gate_accepts_external_positive_labels():
    matrix = family_day_matrix(
        train_counts={"Normal": 1, "DoS": 1, "Reconnaissance": 1},
        validation_counts={"Normal": 1, "DoS": 1, "Reconnaissance": 1},
        test_counts={"Normal": 1, "DoS": 1, "Reconnaissance": 1},
        positive_labels={"DoS", "Reconnaissance"},
    )

    gate = coverage_gate(matrix, positive_labels={"DoS", "Reconnaissance"})

    assert gate["overall_pass"] is True
    assert set(gate["families"]) == {"DoS", "Reconnaissance"}


def test_coverage_gate_default_policy_does_not_recognize_unsw_labels():
    matrix = family_day_matrix(
        train_counts={"Normal": 1, "DoS": 1},
        validation_counts={"Normal": 1, "DoS": 1},
        test_counts={"Normal": 1, "DoS": 1},
    )

    gate = coverage_gate(matrix)

    assert gate["families"] == {}
    assert gate["overall_pass"] is False


def _unsw_frame(rows: int, start_id: int = 1) -> pd.DataFrame:
    categories = ["Normal", "DoS", "Reconnaissance", "Generic"]
    records = []
    for offset in range(rows):
        category = categories[offset % len(categories)]
        records.append(
            {
                "id": start_id + offset,
                "dur": float(offset + 1),
                "spkts": offset + 1,
                "dpkts": offset % 3,
                "sbytes": 100 + offset,
                "dbytes": 50 + offset,
                "attack_cat": category,
                "label": 0 if category == "Normal" else 1,
            }
        )
    return pd.DataFrame.from_records(records)


def test_audit_unsw_corrects_swapped_filenames(tmp_path):
    # Deliberately write the larger official-train frame under the test name.
    _unsw_frame(6, start_id=1).to_csv(tmp_path / "unsw_train.csv", index=False)
    _unsw_frame(10, start_id=1).to_csv(tmp_path / "unsw_test.csv", index=False)

    payload = audit_unsw(str(tmp_path))

    assert payload["provenance"]["filename_swap_corrected"] is True
    assert payload["duplicates"]["raw_rows"] == {"train": 10, "test": 6}
    assert payload["provenance"]["official_split"]["matches_known_split"] is False


def test_audit_unsw_keeps_duplicate_groups_in_one_partition(tmp_path):
    frame = _unsw_frame(20)
    # Duplicate one row's features so a random split would leak it.
    frame = pd.concat([frame, frame.iloc[[0]]], ignore_index=True)
    frame.to_csv(tmp_path / "unsw_train_official.csv", index=False)
    _unsw_frame(10, start_id=100).to_csv(
        tmp_path / "unsw_test_official.csv", index=False
    )

    payload = audit_unsw(str(tmp_path))

    assert payload["duplicates"]["duplicate_rows_within"]["train"] >= 1
    assert payload["group_split"]["train_fraction"] == 0.70


def _cic_frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame.from_records(rows)


def test_audit_cic_single_day_is_insufficient(tmp_path):
    frame = _cic_frame(
        [
            {"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"},
            {"Timestamp": "14/02/2018 08:01:00", "Label": "FTP-BruteForce"},
            {"Timestamp": "14/02/2018 08:02:00", "Label": "SSH-Bruteforce"},
        ]
    )
    frame.to_csv(tmp_path / "cic.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["status"] == "insufficient_days"
    assert payload["capture_days"] == ["2018-02-14"]
    assert payload["temporal_split"]["coverage_gate"]["overall_pass"] is False
    assert payload["label_policy"]["positive_labels"] == []


def test_audit_cic_counts_duplicates_and_suspicious_timestamps(tmp_path):
    frame = _cic_frame(
        [
            {"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"},
            {"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"},
            {"Timestamp": "05/01/1970 00:00:00", "Label": "Benign"},
        ]
    )
    frame.to_csv(tmp_path / "cic.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["rows"]["raw"] == 3
    assert payload["rows"]["duplicate_within_file"] == 1
    assert payload["rows"]["unique"] == 2
    assert payload["rows"]["suspicious_timestamps"] == 1
    assert payload["suspicious_days"] == ["1970-01-05"]


def test_audit_cic_three_days_with_disjoint_families_fails_the_gate(tmp_path):
    _cic_frame(
        [{"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"}]
    ).to_csv(tmp_path / "day1.csv", index=False)
    _cic_frame(
        [{"Timestamp": "15/02/2018 08:00:00", "Label": "DoS"}]
    ).to_csv(tmp_path / "day2.csv", index=False)
    _cic_frame(
        [{"Timestamp": "16/02/2018 08:00:00", "Label": "PortScan"}]
    ).to_csv(tmp_path / "day3.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["status"] == "coverage_fail"
    assert payload["temporal_split"]["coverage_gate"]["overall_pass"] is False
    assert payload["label_policy"]["positive_labels"] == ["DoS", "PortScan"]
    assert payload["temporal_split"]["day_split"] == {
        "2018-02-14": "train",
        "2018-02-15": "validation",
        "2018-02-16": "test",
    }


def test_audit_cic_detects_dos_and_portscan_labels(tmp_path):
    _cic_frame(
        [
            {"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"},
            {"Timestamp": "14/02/2018 08:01:00", "Label": "DoS attacks-Hulk"},
            {"Timestamp": "14/02/2018 08:02:00", "Label": "DDoS attacks-LOIT"},
            {"Timestamp": "14/02/2018 08:03:00", "Label": "PortScan"},
        ]
    ).to_csv(tmp_path / "cic.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["label_policy"]["positive_labels"] == [
        "DDoS",
        "DoS",
        "PortScan",
    ]
    assert payload["label_policy"]["negative_labels"] == ["Benign"]
    assert payload["family_counts"] == {
        "Benign": 1,
        "DDoS": 1,
        "DoS": 1,
        "PortScan": 1,
    }


def test_cic2018_family_does_not_match_substrings():
    assert cic2018_family("DDoS attacks-LOIC-HTTP") == "DDoS"
    assert cic2018_family("DDOS attack-HOIC") == "DDoS"
    assert cic2018_family("DoS attacks-Slowloris") == "DoS"
    assert cic2018_family("PortScan") == "PortScan"
    assert cic2018_family("Dosomething") is None
    assert cic2018_family("Infilteration") is None


def test_audit_cic_removes_repeated_header_rows(tmp_path):
    frame = _cic_frame(
        [
            {"Timestamp": "14/02/2018 08:00:00", "Label": "Benign"},
            {"Timestamp": "Timestamp", "Label": "Label"},
            {"Timestamp": "14/02/2018 08:01:00", "Label": "Benign"},
        ]
    )
    frame.to_csv(tmp_path / "cic.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["rows"]["raw"] == 3
    assert payload["rows"]["header_rows_removed"] == 1
    assert payload["rows"]["unique"] == 2


def test_audit_cic_drops_direct_identifiers_before_hashing(tmp_path):
    # Two flows differ only in Flow ID / Src IP. They must collapse to one flow.
    frame = pd.DataFrame.from_records(
        [
            {
                "Flow ID": "1.1.1.1-2.2.2.2-80-1234-6",
                "Src IP": "1.1.1.1",
                "Src Port": 1234,
                "Dst IP": "2.2.2.2",
                "Dst Port": 80,
                "Protocol": 6,
                "Timestamp": "14/02/2018 08:00:00",
                "Flow Duration": 10,
                "Label": "Benign",
            },
            {
                "Flow ID": "9.9.9.9-2.2.2.2-80-5678-6",
                "Src IP": "9.9.9.9",
                "Src Port": 5678,
                "Dst IP": "2.2.2.2",
                "Dst Port": 80,
                "Protocol": 6,
                "Timestamp": "14/02/2018 08:00:00",
                "Flow Duration": 10,
                "Label": "Benign",
            },
        ]
    )
    frame.to_csv(tmp_path / "cic.csv", index=False)

    payload = audit_cic(str(tmp_path))

    assert payload["rows"]["unique"] == 1
    assert payload["rows"]["duplicate_within_file"] == 1


def test_coverage_gate_reports_required_family_missing_from_dataset():
    matrix = family_day_matrix(
        train_counts={"Benign": 1, "DoS": 1, "DDoS": 1},
        validation_counts={"Benign": 1, "DoS": 1, "DDoS": 1},
        test_counts={"Benign": 1, "DoS": 1, "DDoS": 1},
        positive_labels={"DoS", "DDoS", "PortScan"},
    )

    gate = coverage_gate(
        matrix,
        positive_labels={"DoS", "DDoS", "PortScan"},
        required_families={"DoS", "DDoS", "PortScan"},
    )

    assert gate["overall_pass"] is False
    assert gate["missing_required"] == ["PortScan"]
    assert gate["families"]["PortScan"]["pass"] is False
    assert gate["families"]["PortScan"]["observed"] is False
