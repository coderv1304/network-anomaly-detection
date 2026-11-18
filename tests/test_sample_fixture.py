"""The bundled 500-flow sample: fixture shape and the one-click load endpoint."""

from __future__ import annotations

import importlib.util
import os

import pandas as pd

import app as app_module

FIXTURE = os.path.join("tests", "fixtures", "sample_flows_500.csv")
META = ("Flow ID", "Source IP", "Destination IP", "Timestamp", "Label")


def _client():
    return app_module.app.test_client()


def _fixture_frame() -> pd.DataFrame:
    frame = pd.read_csv(FIXTURE, low_memory=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    return frame


def test_fixture_is_small_deterministic_and_balanced():
    assert os.path.getsize(FIXTURE) < 250 * 1024
    frame = _fixture_frame()
    assert len(frame) == 500
    # 80 model features plus five metadata columns.
    assert len(frame.columns) == 85

    labels = frame["Label"].astype(str).str.strip()
    counts = labels.value_counts().to_dict()
    assert counts == {"BENIGN": 350, "DDoS": 75, "PortScan": 75}

    attack = labels != "BENIGN"
    assert frame.loc[~attack, "Source IP"].nunique() == 12
    assert frame.loc[attack, "Source IP"].nunique() <= 2
    # All attack flows land inside one 300-second accumulator window.
    stamps = pd.to_datetime(frame.loc[attack, "Timestamp"], utc=True)
    assert (stamps.max() - stamps.min()).total_seconds() < 300
    # One accumulator bucket: every attack flow shares the same 300 s window.
    assert len({int(moment.timestamp()) // 300 for moment in stamps}) == 1


def _builder():
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "build_sample_fixture.py"))
    spec = importlib.util.spec_from_file_location("build_sample_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_scores_and_opens_incidents_without_mocked_scores():
    """The committed fixture must alert through the real serving pipeline."""
    report = _builder().score_and_accumulate(FIXTURE)
    assert report["flow_alerts"] >= 1
    assert report["incidents"] >= 1
    assert report["calibration_status"] == "rf-day-based-seed42-isotonic-v1"


def test_fallback_builder_is_deterministic_schema_exact_and_scores(tmp_path):
    """A fresh clone has no raw captures: the fallback must still build a real fixture."""
    import joblib

    builder = _builder()
    first = tmp_path / "fallback_a.csv"
    second = tmp_path / "fallback_b.csv"
    builder.write_fixture(builder._build_fallback(), str(first))
    builder.write_fixture(builder._build_fallback(), str(second))

    # Same seed, same bytes: the fallback is reproducible, not random noise.
    assert first.read_bytes() == second.read_bytes()
    assert first.stat().st_size < 250 * 1024

    frame = pd.read_csv(first, low_memory=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    assert len(frame) == 500
    # The serving schema plus the five metadata columns the ingest path reads.
    assert len(frame.columns) == 85
    features = list(joblib.load(builder.BUNDLE_PATH)["feature_names"])
    assert set(features).issubset(frame.columns)
    assert frame["Label"].astype(str).str.strip().value_counts().to_dict() == {
        "BENIGN": 350,
        "DDoS": 75,
        "PortScan": 75,
    }

    report = builder.score_and_accumulate(str(first))
    assert report["flow_alerts"] >= 1
    assert report["incidents"] >= 1


def test_cli_falls_back_when_the_raw_captures_are_absent(tmp_path):
    builder = _builder()
    output = tmp_path / "fresh_clone_sample.csv"
    exit_code = builder.main(
        [
            "--source-dir",
            str(tmp_path / "no-captures-here"),
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0, "the fresh-clone fallback must build and self-verify"
    assert output.stat().st_size < 250 * 1024


def test_load_sample_endpoint_returns_200_and_surfaces_an_incident():
    app_module._EVIDENCE_ACCUMULATOR.reset()
    response = _client().post("/api/load-sample")
    assert response.status_code == 200

    payload = response.get_json()
    assert payload["provenance"] == "bundled_sample_fixture"
    assert payload["accepted"] == 500
    assert payload["alerts"] >= 1
    assert payload["incidents"] >= 1
    assert payload["elapsed_ms"] < 2000

    incidents = _client().get("/api/incidents?limit=50&open_only=true").get_json()
    assert incidents["count"] >= 1
    assert any(item["source_ip"].startswith("172.16.0.") for item in incidents["incidents"])

    stored = _client().get("/api/flows?limit=500").get_json()
    tagged = [
        flow
        for flow in stored["flows"]
        if (flow.get("provenance") or {}).get("ingestion_source") == "bundled_sample_fixture"
    ]
    assert tagged, "loaded rows must carry the bundled_sample_fixture provenance tag"
