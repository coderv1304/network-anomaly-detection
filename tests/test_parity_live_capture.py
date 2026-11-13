"""Phase P1: lock the live-vs-upload parity findings to the UI contract."""

import json
import os

import pytest

import app as app_module

pytest.importorskip("scapy")
pytest.importorskip("pyflowmeter")

from training import parity_live_capture as parity  # noqa: E402


def _expected_features():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    manifest_path = os.path.join(
        project_root, "models", "model_manifest_rf_day_based_seed42.json"
    )
    with open(manifest_path, encoding="utf-8") as handle:
        return json.load(handle)["features"]


def test_fixed_feature_lists_are_locked():
    # Historical regression lists: everything in these lists must now be
    # produced by the upload parser (see coverage assertions below).
    assert len(parity.FIXED_MISSING_FEATURES) == 23
    assert len(parity.FIXED_DUMMY_FEATURES) == 6
    assert len(set(parity.FIXED_MISSING_FEATURES) | set(parity.FIXED_DUMMY_FEATURES)) == 29

    audit = app_module._PARITY_AUDIT
    assert audit["required_features"] == 80
    assert audit["generated_features"] == 80
    assert audit["missing_features"] == 0
    assert audit["dummy_features"] == 0
    assert audit["missing_list"] == []
    assert audit["dummy_list"] == []
    assert audit["known_divergences"], "the live-path divergences must stay documented"


def test_fixture_reports_live_and_upload_schema_coverage(tmp_path):
    expected = _expected_features()
    assert len(expected) == 80

    pcap_path = str(tmp_path / "fixture.pcap")
    parity.build_fixture_pcap(pcap_path)

    live_flows, live_error = parity.run_pyflowmeter(pcap_path)
    reference_frame, packet_count, reference_error = parity.run_pcap_parser(pcap_path)

    assert live_error is None
    assert reference_error is None
    assert packet_count == 14
    assert len(live_flows) == 4
    assert reference_frame is not None
    assert len(reference_frame) == 6

    live_sample = parity.map_features(live_flows[0], expected)
    reference_sample = parity.map_features(reference_frame.iloc[0].to_dict(), expected)
    assert len(live_sample) == 80
    # The parity fix: the upload path now covers the full 80-feature schema.
    assert len(reference_sample) == 80
    for feature in parity.FIXED_MISSING_FEATURES + parity.FIXED_DUMMY_FEATURES:
        assert feature in reference_sample, f"upload parser regressed: {feature}"

    comparison = parity.compare(live_flows, reference_frame, expected)
    assert comparison["matched_flows"] == 4
    assert comparison["unmatched_live_flows"] == []
    assert comparison["ambiguous_flows"] == []
    assert len(comparison["reference_only_flows"]) == 2

    reference_only_protocols = {
        entry["key"][0] for entry in comparison["reference_only_flows"]
    }
    assert reference_only_protocols == {1, 6}  # ICMP and IPv6 TCP
