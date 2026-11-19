"""Contract tests for the ONNX export bridge and the committed artifacts.

These tests do not re-train the model. They pin the model SHA-256, assert the
24-input model schema matches the Go sensor, and re-run the 1,000-row parity
fixture through ONNX Runtime against the recorded scikit-learn reference.
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
    PROJECT_ROOT, "capture", "internal", "flow", "features.go"
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
    # The canonical training schema lives in schema.go (netshield-flow-v1, 26
    # features). This test pins the shipped model's own 24-input order, which
    # the Go sensor declares as ModelFeatureNames.
    with open(FEATURE_SOURCE, "r", encoding="utf-8") as handle:
        source = handle.read()
    match = re.search(
        r"var ModelFeatureNames = \[\]string\{(?P<body>.*?)\}", source, re.S
    )
    assert match, "could not locate ModelFeatureNames in features.go"
    return re.findall(r'"([^"]+)"', match.group("body"))


def test_manifest_pins_the_sensor_schema(manifest):
    from training.export_onnx import FEATURE_NAMES

    assert manifest["feature_names"] == list(FEATURE_NAMES)
    assert manifest["feature_names"] == _go_feature_names()
    assert len(manifest["feature_names"]) == 24
    assert manifest["classes"] == ["BENIGN", "ATTACK"]
    assert manifest["onnx_input"] == "X"
    assert manifest["onnx_output"] == "probabilities"
    assert 0.0 < float(manifest["threshold"]) < 1.0
    assert manifest["calibration_method"] == "validation_f1_sweep"


def test_fallback_matches_schema_and_is_finite(manifest):
    fallback = manifest["fallback"]
    assert fallback["type"] == "logistic"
    assert fallback["activation"] == "sigmoid"
    assert len(fallback["weights"]) == len(manifest["feature_names"])
    assert np.all(np.isfinite(np.asarray(fallback["weights"], dtype=np.float64)))
    assert np.isfinite(float(fallback["bias"]))


def test_model_sha256_matches_manifest_and_parity(manifest, parity):
    with open(MODEL_PATH, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()
    assert digest == manifest["sha256"]
    assert digest == parity["onnx_sha256"]


def test_onnx_parity_over_one_thousand_rows(manifest, parity):
    ort = pytest.importorskip("onnxruntime")
    rows = parity["rows"]
    assert len(rows) == 1000
    features = np.asarray([row["features"] for row in rows], dtype=np.float32)
    assert features.shape == (1000, 24)
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
    assert inputs[0].shape == [None, 24]
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
        "Flow Duration": 1_500_000,
        "Total Fwd Packets": 3,
        "Total Backward Packets": 2,
        "Total Length of Fwd Packets": 300,
        "Total Length of Bwd Packets": 200,
        "Fwd Header Length": 60,
        "Bwd Header Length": 40,
        "Packet Length Mean": 100,
        "Packet Length Std": 10,
        "Flow IAT Mean": 5000,
        "Flow IAT Std": 2500,
        "FIN Flag Count": 1,
        "SYN Flag Count": 2,
        "RST Flag Count": 1,
        "PSH Flag Count": 1,
        "ACK Flag Count": 2,
        "Label": "BENIGN",
    }
    values = derive_features(pd.DataFrame([row]))[0]
    by_name = dict(zip(FEATURE_NAMES, values))

    assert by_name["duration_sec"] == pytest.approx(1.5)
    assert by_name["fwd_bwd_pkt_ratio"] == pytest.approx(1.5)
    assert by_name["fwd_bwd_byte_ratio"] == pytest.approx(1.5)
    assert by_name["syn_ack_ratio"] == pytest.approx(1.0)
    assert by_name["fin_rst_ratio"] == pytest.approx(0.4)
    assert by_name["mean_pkt_size"] == pytest.approx(100.0)
    assert by_name["iat_cv"] == pytest.approx(0.5)
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
