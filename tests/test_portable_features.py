"""Tests for the ratio-only portable feature transform."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from training.portable_features import (
    PORTABLE_FEATURE_NAMES,
    PORTABLE_INPUT_COLUMNS,
    portable_dataframe,
    portable_matrix,
    portable_matrix_from_tier_a,
    schema_payload,
)


def test_schema_is_stable_and_small():
    schema = schema_payload()
    assert schema["count"] == 8
    assert schema["features"] == list(PORTABLE_FEATURE_NAMES)
    assert schema["inputs"] == list(PORTABLE_INPUT_COLUMNS)
    assert len(schema["sha256"]) == 64
    assert schema_payload() == schema


def test_transform_ignores_duration_and_flags():
    frame = pd.DataFrame(
        {
            "total_fwd_packets": [10.0, 10.0],
            "total_backward_packets": [5.0, 5.0],
            "total_length_of_fwd_packets": [1000.0, 1000.0],
            "total_length_of_bwd_packets": [500.0, 500.0],
            "flow_duration": [1.0, 999999.0],
            "syn_flag_count": [0.0, 10.0],
        }
    )
    result = portable_dataframe(frame)
    assert list(result.columns) == list(PORTABLE_FEATURE_NAMES)
    # The transform never reads duration or flags: identical inputs -> identical row.
    assert np.allclose(result.iloc[0].to_numpy(), result.iloc[1].to_numpy())


def test_ratios_are_bounded_and_finite_for_zero_flows():
    matrix = portable_matrix(
        fwd_packets=np.array([0.0, 3.0, np.nan, -2.0]),
        bwd_packets=np.array([0.0, 1.0, 4.0, 0.0]),
        fwd_bytes=np.array([0.0, 300.0, 10.0, 0.0]),
        bwd_bytes=np.array([0.0, 100.0, -5.0, 0.0]),
    )
    assert matrix.shape == (4, len(PORTABLE_FEATURE_NAMES))
    assert np.isfinite(matrix).all()
    assert (matrix >= 0.0).all()
    ratio_columns = [3, 4, 5, 7]
    assert (matrix[:, ratio_columns] <= 1.0 + 1e-6).all()
    assert np.allclose(matrix[0], 0.0)


def test_per_packet_values_match_hand_calculation():
    matrix = portable_matrix(
        fwd_packets=np.array([2.0]),
        bwd_packets=np.array([2.0]),
        fwd_bytes=np.array([200.0]),
        bwd_bytes=np.array([40.0]),
    )[0]
    assert matrix[0] == pytest.approx(np.log1p(60.0))
    assert matrix[1] == pytest.approx(np.log1p(100.0))
    assert matrix[2] == pytest.approx(np.log1p(20.0))
    assert matrix[3] == pytest.approx(0.5)
    assert matrix[4] == pytest.approx(1.0)
    assert matrix[5] == pytest.approx(200.0 / 240.0)
    assert matrix[6] == pytest.approx(np.log1p(40.0 / 200.0))
    assert matrix[7] == pytest.approx(80.0 / 120.0)


def test_output_is_scale_invariant_for_same_shape_traffic():
    """A uniform byte/packet scaling must not change any ratio feature."""
    small = portable_matrix(
        np.array([4.0]),
        np.array([4.0]),
        np.array([400.0]),
        np.array([200.0]),
    )
    large = portable_matrix(
        np.array([4.0]),
        np.array([4.0]),
        np.array([4000.0]),
        np.array([2000.0]),
    )
    # Per-packet log features shift by log(10), but every ratio is identical.
    assert small[0, 3:] == pytest.approx(large[0, 3:])
    assert small[0, 5] == pytest.approx(large[0, 5])
    assert small[0, 7] == pytest.approx(large[0, 7])


def test_matrix_input_matches_dataframe_input():
    columns = list(PORTABLE_INPUT_COLUMNS)
    matrix = np.array([[4.0, 2.0, 400.0, 200.0]])
    direct = portable_matrix_from_tier_a(matrix, columns)
    via_frame = portable_matrix_from_tier_a(
        pd.DataFrame(matrix, columns=columns), columns
    )
    assert np.allclose(direct, via_frame)


def test_missing_input_columns_fail_loudly():
    with pytest.raises(KeyError, match="missing Tier A columns"):
        portable_matrix_from_tier_a(np.zeros((1, 2)), ["total_fwd_packets", "x"])
