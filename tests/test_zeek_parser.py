"""Tests for the optional Zeek ``conn.log`` parser."""

from __future__ import annotations

import csv
import io
import json
import os

import numpy as np
import pytest

from training.portable_features import PORTABLE_FEATURE_NAMES, portable_matrix
from zeek_parser import (
    TIER_A_COLUMNS,
    iter_conn_records,
    main,
    record_to_flow,
    record_to_portable,
    record_to_tier_a,
    write_tier_a_csv,
    zeek_to_flows,
    zeek_to_portable_rows,
)

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "zeek_conn.log")

JSON_LINES = "\n".join(
    [
        json.dumps(
            {
                "_path": "conn",
                "ts": 1700000010.0,
                "uid": "J1",
                "id.orig_h": "10.0.0.5",
                "id.orig_p": 50000,
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 443,
                "proto": "tcp",
                "duration": 0.5,
                "orig_bytes": 100,
                "resp_bytes": 900,
                "conn_state": "SF",
                "orig_pkts": 2,
                "orig_ip_bytes": 140,
                "resp_pkts": 3,
                "resp_ip_bytes": 1000,
            }
        ),
        "{not valid json",
        json.dumps({"_path": "http", "uid": "H1", "host": "example.com"}),
        json.dumps(
            {
                "_path": "conn",
                "uid": "J2",
                "id.orig_h": "10.0.0.7",
                "id.orig_p": 50001,
                "id.resp_h": "10.0.0.8",
                "id.resp_p": 80,
                "proto": "udp",
                "conn_state": "S0",
            }
        ),
    ]
)


def test_tsv_fixture_is_read_with_headers():
    records = list(iter_conn_records(FIXTURE))
    assert len(records) == 3
    assert records[0]["uid"] == "C1"
    assert records[0]["id.orig_h"] == "10.0.0.5"
    assert records[1]["conn_state"] == "S0"


def test_json_lines_skip_malformed_and_non_conn_records():
    records = list(iter_conn_records(io.StringIO(JSON_LINES)))
    assert [record["uid"] for record in records] == ["J1", "J2"]
    assert records[0]["id.resp_h"] == "1.1.1.1"


def test_record_to_flow_maps_canonical_names_and_flags():
    record = next(iter(iter_conn_records(FIXTURE)))
    flow = record_to_flow(record)
    assert flow["src_ip"] == "10.0.0.5"
    assert flow["dst_ip"] == "93.184.216.34"
    assert flow["src_port"] == 49152
    assert flow["dst_port"] == 443
    assert flow["protocol"] == "TCP"
    assert flow["protocol_number"] == 6
    assert flow["flow_id"] == "C1"
    assert flow["flow_duration"] == pytest.approx(1_500_000.0)
    assert flow["tot_fwd_pkts"] == 8
    assert flow["tot_bwd_pkts"] == 10
    assert flow["totlen_fwd_pkts"] == 1600
    assert flow["totlen_bwd_pkts"] == 6000
    assert flow["flow_pkts_s"] == pytest.approx(18 / 1.5)
    assert flow["flow_byts_s"] == pytest.approx(7600 / 1.5)
    assert flow["pkt_len_mean"] == pytest.approx(7600 / 18)
    assert flow["syn_flag_cnt"] == 1
    assert flow["fin_flag_cnt"] == 1
    assert flow["rst_flag_cnt"] == 0


def test_zero_duration_scan_does_not_divide_by_zero():
    records = list(iter_conn_records(FIXTURE))
    flow = record_to_flow(records[1])
    assert flow["flow_duration"] == 0.0
    assert flow["flow_pkts_s"] == 0.0
    assert flow["flow_byts_s"] == 0.0
    assert flow["pkt_len_mean"] == 60.0
    assert flow["syn_flag_cnt"] == 1
    assert flow["rst_flag_cnt"] == 0


def test_tier_a_maxima_are_unavailable_not_fabricated():
    tier_a = record_to_tier_a(next(iter(iter_conn_records(FIXTURE))))
    assert list(tier_a) == list(TIER_A_COLUMNS)
    assert tier_a["packet_length_max"] is None
    assert tier_a["total_fwd_packets"] == 8
    assert tier_a["packet_length_mean"] == pytest.approx(7600 / 18)


def test_portable_row_matches_shared_transform():
    record = next(iter(iter_conn_records(FIXTURE)))
    row = record_to_portable(record)
    expected = portable_matrix(
        np.array([8.0]), np.array([10.0]), np.array([1600.0]), np.array([6000.0])
    )[0]
    assert list(row) == list(PORTABLE_FEATURE_NAMES)
    assert np.allclose([row[name] for name in PORTABLE_FEATURE_NAMES], expected)


def test_max_records_limits_both_conversions():
    assert len(zeek_to_flows(FIXTURE, max_records=2)) == 2
    assert len(zeek_to_portable_rows(FIXTURE, max_records=1)) == 1


def test_write_tier_a_csv_keeps_empty_maximum(tmp_path):
    destination = tmp_path / "tier_a.csv"
    count = write_tier_a_csv(str(FIXTURE), str(destination))
    assert count == 3
    with open(destination, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 3
    assert rows[0]["packet_length_max"] == ""
    assert rows[0]["flow_duration"] == "1500000.0"
    assert set(TIER_A_COLUMNS).issubset(rows[0].keys())


def test_cli_prints_portable_json(capsys):
    assert main([FIXTURE, "--portable", "--max-records", "1"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload) == 1
    assert set(payload[0]) == set(PORTABLE_FEATURE_NAMES)
