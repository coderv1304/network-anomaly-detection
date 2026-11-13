"""Hand-computed tests for the CIDDS-002 scanning audit.

These tests use synthetic frames and temporary directories. They never read the
production download, the score caches, or the serving artifact.
"""

from __future__ import annotations

import pandas as pd
import pytest

from scripts.cidds002_audit import (
    EXPECTED_COLUMNS,
    audit_cidds,
    row_family,
    scan_type,
)

BOUNDARY = pd.Timestamp("2017-08-11 12:00:00")


def _log_frame() -> pd.DataFrame:
    """A 43-row attack log matching the published CIDDS-002 release."""
    records = []
    for activity_id in range(1, 44):
        if activity_id <= 20:
            start = pd.Timestamp("2017-08-03 10:00:00")
            end = pd.Timestamp("2017-08-03 11:00:00")
        elif activity_id <= 28:
            start = pd.Timestamp("2017-08-10 10:00:00")
            end = pd.Timestamp("2017-08-10 11:00:00")
        elif activity_id == 29:
            start = pd.Timestamp("2017-08-11 11:00:00")
            end = BOUNDARY
        else:
            start = pd.Timestamp("2017-08-12 10:00:00")
            end = pd.Timestamp("2017-08-12 11:00:00")
        records.append(
            {
                "start": start,
                "end": end,
                "duration": "0:00:00",
                "activity": "scan",
                "errorCode": 0,
                "description": "nmap args: -sS -T 2",
                "IP": "192.168.220.51",
                "activityID": activity_id,
            }
        )
    return pd.DataFrame.from_records(records)


def _row(
    timestamp: str,
    label: str = "normal",
    attack_type: str = "---",
    attack_id: int | None = None,
    description: str = "---",
    src_pt: int = 40000,
    **overrides,
) -> dict:
    record = {
        "Date first seen": timestamp,
        "Duration": 0.001,
        "Proto": "TCP",
        "Src IP Addr": "192.168.220.51",
        "Src Pt": src_pt,
        "Dst IP Addr": "192.168.100.11",
        "Dst Pt": 80,
        "Packets": 2,
        "Bytes": 120,
        "Flows": 1,
        "Flags": ".A....",
        "Tos": 0,
        "label": label,
        "attackType": attack_type,
        "attackID": attack_id,
        "attackDescription": description,
    }
    record.update(overrides)
    return record


def _write_dataset(tmp_path, week1_rows, week2_rows, nested: bool = False):
    root = tmp_path / "CIDDS-002" if nested else tmp_path
    (root / "traffic").mkdir(parents=True)
    (root / "attack_logs").mkdir(parents=True)
    pd.DataFrame.from_records(week1_rows, columns=EXPECTED_COLUMNS).to_csv(
        root / "traffic" / "week1.csv", index=False
    )
    pd.DataFrame.from_records(week2_rows, columns=EXPECTED_COLUMNS).to_csv(
        root / "traffic" / "week2.csv", index=False
    )
    _log_frame().to_csv(root / "attack_logs" / "attacks_logs_intern.csv", index=False)
    return tmp_path if nested else root


def test_scan_type_maps_nmap_arguments():
    assert scan_type("nmap args: -sS -T 2") == "SYN"
    assert scan_type("nmap args: -sA -T 3") == "ACK"
    assert scan_type("nmap args: -sF -T 1") == "FIN"
    assert scan_type("nmap args: -sU -T 0 ") == "UDP"
    assert scan_type("nmap args: -n -sP -PE -T 2") == "PingSweep"
    assert scan_type("---") == "None"


def test_row_family_excludes_victim_and_splits_ping_sweep():
    assert row_family("normal", "---", "---") == "Normal"
    assert row_family("attacker", "scan", "nmap args: -sS -T 2") == "PortScan"
    assert row_family("attacker", "scan", "nmap args: -sF -T 1") == "PortScan"
    assert row_family("attacker", "scan", "nmap args: -n -sP -PE -T 1") == "PingSweep"
    assert row_family("victim", "scan", "nmap args: -sS -T 2") == "Excluded"
    assert row_family("normal", "---", "---") != "Excluded"


def _coverage_dataset(tmp_path):
    week1 = [
        _row("2017-08-02 10:00:00", src_pt=40001),
        _row("2017-08-02 10:00:01", src_pt=40002),
        _row("2017-08-02 10:00:02", src_pt=40003),
        _row(
            "2017-08-03 10:00:00",
            label="attacker",
            attack_type="scan",
            attack_id=1,
            description="nmap args: -sS -T 2",
            src_pt=40004,
        ),
        _row(
            "2017-08-03 10:00:01",
            label="attacker",
            attack_type="scan",
            attack_id=1,
            description="nmap args: -sS -T 2",
            src_pt=40005,
        ),
        _row(
            "2017-08-03 10:00:02",
            label="victim",
            attack_type="scan",
            attack_id=1,
            description="nmap args: -sS -T 2",
            src_pt=40006,
        ),
    ]
    week2 = [
        _row("2017-08-10 10:00:00", src_pt=40007),
        _row("2017-08-10 10:00:01", src_pt=40008),
        _row(
            "2017-08-10 10:00:02",
            label="attacker",
            attack_type="scan",
            attack_id=21,
            description="nmap args: -sS -T 2",
            src_pt=40009,
        ),
        _row("2017-08-12 10:00:00", src_pt=40010),
        _row("2017-08-12 10:00:01", src_pt=40011),
        _row(
            "2017-08-12 10:00:02",
            label="attacker",
            attack_type="scan",
            attack_id=30,
            description="nmap args: -sF -T 1",
            src_pt=40012,
        ),
        _row(
            "2017-08-12 10:00:03",
            label="attacker",
            attack_type="scan",
            attack_id=31,
            description="nmap args: -n -sP -PE -T 1",
            src_pt=40013,
        ),
    ]
    return _write_dataset(tmp_path, week1, week2)


def test_audit_cidds_passes_the_coverage_gate(tmp_path):
    directory = _coverage_dataset(tmp_path)

    payload = audit_cidds(str(directory))

    assert payload["status"] == "coverage_pass"
    assert payload["temporal_split"]["coverage_gate"]["overall_pass"] is True
    parts = payload["temporal_split"]["partitions"]
    assert parts["train"]["label_counts"]["PortScan"] == 2
    assert parts["validation"]["label_counts"]["PortScan"] == 1
    assert parts["test"]["label_counts"]["PortScan"] == 1
    assert parts["train"]["label_counts"]["Normal"] == 3
    assert parts["validation"]["label_counts"]["Normal"] == 2
    assert parts["test"]["label_counts"]["Normal"] == 2
    # Victim flows are excluded from every partition.
    assert "Excluded" not in parts["train"]["label_counts"]


def test_audit_cidds_splits_ping_sweep_out_of_portscan(tmp_path):
    directory = _coverage_dataset(tmp_path)

    payload = audit_cidds(str(directory))

    parts = payload["temporal_split"]["partitions"]
    assert parts["test"]["label_counts"]["PingSweep"] == 1
    assert parts["test"]["label_counts"]["PortScan"] == 1
    assert payload["temporal_split"]["coverage_gate"]["families"]["PortScan"]["test"] == 1


def test_audit_cidds_uses_the_attack_boundary_not_midnight(tmp_path):
    directory = _coverage_dataset(tmp_path)

    payload = audit_cidds(str(directory))

    assert payload["temporal_split"]["boundary"] == BOUNDARY.isoformat()
    assert payload["temporal_split"]["validation_window"][1] == BOUNDARY.isoformat()


def test_audit_cidds_counts_exact_duplicates(tmp_path):
    week1 = [
        _row("2017-08-02 10:00:00", src_pt=40001),
        _row("2017-08-02 10:00:00", src_pt=40001),
    ]
    week2 = [_row("2017-08-10 10:00:00", src_pt=40002)]
    directory = _write_dataset(tmp_path, week1, week2)

    payload = audit_cidds(str(directory))

    assert payload["rows"]["raw"] == 3
    assert payload["rows"]["duplicate_rows"] == 1
    assert payload["rows"]["unique_flow_keys"] == 2


def test_audit_cidds_keeps_feature_only_duplicates(tmp_path):
    # Same counters, different start time: legitimate repeated NetFlow traffic.
    week1 = [
        _row("2017-08-02 10:00:00", src_pt=40001),
        _row("2017-08-02 10:00:05", src_pt=40001),
    ]
    week2 = [_row("2017-08-10 10:00:00", src_pt=40002)]
    directory = _write_dataset(tmp_path, week1, week2)

    payload = audit_cidds(str(directory))

    assert payload["rows"]["feature_only_duplicates_not_removed"] == 1
    assert payload["rows"]["duplicate_rows"] == 0
    assert payload["rows"]["unique_flow_keys"] == 3


def test_audit_cidds_fails_when_validation_has_no_portscan(tmp_path):
    week1 = [
        _row("2017-08-02 10:00:00", src_pt=40001),
        _row(
            "2017-08-03 10:00:00",
            label="attacker",
            attack_type="scan",
            attack_id=1,
            description="nmap args: -sS -T 2",
            src_pt=40002,
        ),
    ]
    week2 = [
        _row("2017-08-10 10:00:00", src_pt=40003),
        _row(
            "2017-08-12 10:00:00",
            label="attacker",
            attack_type="scan",
            attack_id=30,
            description="nmap args: -sF -T 1",
            src_pt=40004,
        ),
    ]
    directory = _write_dataset(tmp_path, week1, week2)

    payload = audit_cidds(str(directory))

    assert payload["status"] == "coverage_fail"
    assert payload["temporal_split"]["coverage_gate"]["overall_pass"] is False
    assert payload["temporal_split"]["coverage_gate"]["families"]["PortScan"]["validation"] == 0


def test_audit_cidds_accepts_a_nested_release_folder(tmp_path):
    week1 = [_row("2017-08-02 10:00:00", src_pt=40001)]
    week2 = [_row("2017-08-10 10:00:00", src_pt=40002)]
    directory = _write_dataset(tmp_path, week1, week2, nested=True)

    payload = audit_cidds(str(directory))

    assert payload["provenance"]["directory"].endswith("CIDDS-002")
    assert payload["rows"]["raw"] == 2


def test_audit_cidds_rejects_a_truncated_attack_log(tmp_path):
    week1 = [_row("2017-08-02 10:00:00", src_pt=40001)]
    week2 = [_row("2017-08-10 10:00:00", src_pt=40002)]
    directory = _write_dataset(tmp_path, week1, week2)
    (directory / "attack_logs" / "attacks_logs_intern.csv").write_text(
        "start,end,duration,activity,errorCode,description,IP,activityID\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="43"):
        audit_cidds(str(directory))
