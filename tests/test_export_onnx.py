"""Contract tests for the ONNX export bridge and the committed artifacts.

These tests do not re-train the model. They pin the model SHA-256, assert the
canonical 26-feature ``netshield-flow-v1`` schema matches the Go sensor, and
re-run the 1,000-row parity fixture through ONNX Runtime against the recorded
scikit-learn reference.
"""

from __future__ import annotations

import hashlib
import json
import os
import re

import numpy as np
import pandas as pd
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "netshield_flow.onnx")
MANIFEST_PATH = os.path.join(PROJECT_ROOT, "models", "netshield_flow_manifest.json")
PARITY_PATH = os.path.join(PROJECT_ROOT, "models", "netshield_flow_parity.json")
FEATURE_SOURCE = os.path.join(
    PROJECT_ROOT, "capture", "internal", "flow", "schema.go"
)
EXPECTED_SCHEMA_SHA256 = (
    "6ef22a3b0fdecdf3fb5119e5d7694c61ab9f920e52b993eb599fd924ab1de772"
)


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture(scope="module")
def manifest() -> dict:
    return _load_json(MANIFEST_PATH)


@pytest.fixture(scope="module")
def parity() -> dict:
    return _load_json(PARITY_PATH)


def _go_feature_names() -> list[str]:
    with open(FEATURE_SOURCE, "r", encoding="utf-8") as handle:
        source = handle.read()
    match = re.search(
        r"var FeatureNames = \[\]string\{(?P<body>.*?)\}", source, re.S
    )
    assert match, "could not locate FeatureNames in schema.go"
    return re.findall(r'"([^"]+)"', match.group("body"))


def test_manifest_pins_the_sensor_schema(manifest):
    from training.export_onnx import FEATURE_NAMES, SCHEMA_SHA256, SCHEMA_VERSION

    assert manifest["schema_version"] == SCHEMA_VERSION == "netshield-flow-v1"
    assert manifest["feature_names"] == list(FEATURE_NAMES)
    assert manifest["feature_names"] == _go_feature_names()
    assert len(manifest["feature_names"]) == 26
    digest = hashlib.sha256(
        ",".join(manifest["feature_names"]).encode("utf-8")
    ).hexdigest()
    assert manifest["schema_sha256"] == digest == SCHEMA_SHA256
    assert digest == EXPECTED_SCHEMA_SHA256
    assert manifest["classes"] == ["BENIGN", "ATTACK"]
    assert manifest["onnx_input"] == "X"
    assert manifest["onnx_output"] == "probabilities"
    assert manifest["target_opset"] == 15
    assert 0.0 < float(manifest["threshold"]) < 1.0


def test_linear_fallback_matches_schema_and_is_finite(manifest):
    fallback = manifest["linear_fallback"]
    count = len(manifest["feature_names"])
    assert fallback["type"] == "logistic"
    assert fallback["activation"] == "sigmoid"
    for key in ("means", "stds", "weights"):
        values = np.asarray(fallback[key], dtype=np.float64)
        assert values.shape == (count,)
        assert np.all(np.isfinite(values))
    assert np.all(np.asarray(fallback["stds"], dtype=np.float64) > 0.0)
    assert np.isfinite(float(fallback["bias"]))


def test_model_sha256_matches_manifest_and_parity(manifest, parity):
    with open(MODEL_PATH, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert digest == manifest["onnx_sha256"]
    assert digest == parity["onnx_sha256"]
    assert parity["schema_sha256"] == manifest["schema_sha256"]
    assert parity["feature_names"] == manifest["feature_names"]


def test_onnx_parity_over_one_thousand_rows(manifest, parity):
    ort = pytest.importorskip("onnxruntime")
    rows = parity["rows"]
    assert len(rows) == 1000
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    assert features.shape == (1000, 26)
    assert np.all(np.isfinite(features))
    onnx_probabilities = np.asarray(
        [row["onnx_probability"] for row in rows], dtype=np.float64
    )
    reference_probabilities = np.asarray(
        [row["sklearn_probability"] for row in rows], dtype=np.float64
    )

    session = ort.InferenceSession(
        MODEL_PATH, providers=["CPUExecutionProvider"]
    )
    inputs = session.get_inputs()
    outputs = session.get_outputs()
    assert inputs[0].name == manifest["onnx_input"]
    assert inputs[0].shape == [None, 26]
    assert any(output.name == manifest["onnx_output"] for output in outputs)

    live = np.asarray(
        session.run(
            [manifest["onnx_output"]], {inputs[0].name: features}
        )[0],
        dtype=np.float64,
    )
    assert live.shape == (1000, 2)
    probabilities = live[:, 1]
    assert np.all((probabilities >= 0.0) & (probabilities <= 1.0))

    maximum = float(np.max(np.abs(probabilities - reference_probabilities)))
    assert maximum < parity["tolerance"]
    assert maximum < 1e-5
    # The stored fixture must still describe the committed model.
    assert np.max(np.abs(probabilities - onnx_probabilities)) < 1e-6


def test_derived_features_match_sensor_semantics():
    from training.export_onnx import FEATURE_NAMES, derive_features

    row = {
        "Protocol": 6,
        "Flow Duration": 1_500_000,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 300,
        "Total Length of Bwd Packets": 200,
        "Fwd Header Length": 60,
        "Bwd Header Length": 40,
        "Packet Length Mean": 100,
        "Packet Length Std": 10,
        "Max Packet Length": 240,
        "Flow IAT Mean": 5000,
        "Flow IAT Std": 2500,
        "Flow IAT Max": 9000,
        "FIN Flag Count": 1,
        "SYN Flag Count": 2,
        "RST Flag Count": 1,
        "PSH Flag Count": 1,
        "ACK Flag Count": 2,
        "URG Flag Count": 1,
        "ECE Flag Count": 0,
        "CWE Flag Count": 0,
        "Label": "BENIGN",
    }
    values = derive_features(pd.DataFrame([row]))[0]
    assert values.shape == (26,)
    by_name = dict(zip(FEATURE_NAMES, values))

    assert by_name["protocol"] == pytest.approx(6)
    assert by_name["duration_sec"] == pytest.approx(1.5)
    assert by_name["fwd_bwd_pkt_ratio"] == pytest.approx(1.5)
    assert by_name["syn_ack_ratio"] == pytest.approx(1.0)
    assert by_name["flow_iat_max"] == pytest.approx(9000)
    assert by_name["pkt_len_max"] == pytest.approx(240)
    assert by_name["urg_cnt"] == pytest.approx(1)
    assert by_name["bytes_per_sec"] == pytest.approx(500.0 / 1.5)
    assert by_name["pkts_per_sec"] == pytest.approx(5.0 / 1.5)
    assert np.all(np.isfinite(values))

    # A zero-duration flow still produces finite rates via the epsilon floor.
    degenerate = dict(row)
    degenerate["Flow Duration"] = 0
    values = derive_features(pd.DataFrame([degenerate]))[0]
    by_name = dict(zip(FEATURE_NAMES, values))
    assert by_name["duration_sec"] == pytest.approx(1e-6)
    assert np.all(np.isfinite(values))
