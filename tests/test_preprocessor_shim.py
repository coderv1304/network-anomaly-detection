"""Regression tests for legacy ``preprocessor`` pickle imports."""

from __future__ import annotations

import os

import joblib
import pytest

from preprocessor import FlowSanitizer
from training.preprocessor import FlowSanitizer as CanonicalFlowSanitizer

IF_BUNDLE = os.path.join("models", "model_bundle_if_day_based_seed42.pkl")


def test_shim_exports_the_canonical_implementation():
    assert FlowSanitizer is CanonicalFlowSanitizer


def test_isolation_forest_bundle_unpickles_through_the_shim():
    if not os.path.isfile(IF_BUNDLE):
        pytest.skip("Isolation Forest bundle is not present")
    bundle = joblib.load(IF_BUNDLE)
    assert "pipeline" in bundle
    assert bundle["feature_names"]
    assert bundle["threshold"] is not None
