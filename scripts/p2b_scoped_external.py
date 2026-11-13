#!/usr/bin/env python
"""P2B scoped external supervised comparison on CIC-IDS-2018.

The preregistered P2B protocol uses the CIC-IDS-2017 day split. That split
cannot fit a supervised volumetric/scanning head: Monday-Tuesday contains zero
target positives, and the Wednesday validation families are disjoint from the
Friday test families. This script executes the approved A4-scoped amendment:
a leakage-safe group split of CIC-IDS-2018 for DoS and DDoS only.

The scope is deliberately narrow:

* positive families: DoS and DDoS;
* PortScan is absent from CIC-IDS-2018 and is not claimed;
* the serving artifact, registry row, and threshold are untouched;
* thresholds are selected on validation only and applied once to test.

It compares the five Tier A rules against Logistic Regression, Random Forest,
and Isolation Forest at 10 and 100 alerts per 10,000 flows across five seeds.

Examples:
    venv/Scripts/python.exe scripts/p2b_scoped_external.py \
        --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete"

    # Fast pipeline check; writes to scratch/ instead of docs/
    venv/Scripts/python.exe scripts/p2b_scoped_external.py --max-rows 50000 \
        --seeds 42 --output scratch/p2b_smoke.json --report scratch/p2b_smoke.md
"""

from __future__ import annotations

import argparse
import collections
import gc
import json
import math
import os
import sys
import time
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from scipy.stats import binomtest
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.cross_dataset_transfer import (  # noqa: E402
    _full_feature_hashes,
    cic2018_feature_frame,
    schema_payload,
)
from scripts.external_dataset_audit import (  # noqa: E402
    CIC_METADATA_COLUMNS,
    CIC_PII_COLUMNS,
    TIER_A_FEATURES,
    cic2018_family,
)
from scripts.prevalence_eval import (  # noqa: E402
    alerts_per_10k,
    break_even_per_flow,
    clopper_pearson_upper,
    ppv_at_prevalence,
    wilson_interval,
)
from scripts.rule_baselines import (  # noqa: E402
    _finite_or_none,
    _sha256_file,
    alert_budget_k,
    bootstrap_prevalence,
    build_rule_scores,
    confusion_counts,
    fit_rule_normalization,
    select_budget_threshold,
)
from training.model_registry import (  # noqa: E402
    feature_schema_sha256,
    feature_schema_version,
)

ARTIFACT_VERSION = "p2b-scoped-cic2018-v1"
DEFAULT_CIC_DIR = os.path.expanduser(
    os.path.join("~", "Downloads", "CIC IDS 2018 Complete")
)
RESULTS_JSON = os.path.join(PROJECT_ROOT, "docs", "p2b_scoped_external.json")
REPORT = os.path.join(PROJECT_ROOT, "docs", "P2B_SCOPED_EXTERNAL.md")
MODEL_BUNDLE = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_p2b_cic2018_scoped_seed42.pkl"
)
MODEL_MANIFEST = os.path.join(
    PROJECT_ROOT, "models", "model_manifest_p2b_cic2018_scoped_seed42.json"
)

BUDGETS = (10, 100)
DEFAULT_SEEDS = (42, 43, 44, 45, 46)
TRAIN_CAP = 800_000
BOOTSTRAP_DRAWS = 2_000
PREVALENCES = (0.0001, 0.001, 0.01, 0.10)
ECE_BINS = 10

POSITIVE_FAMILIES = ("DoS", "DDoS")
NEGATIVE_FAMILY = "Benign"
SCOPE_STATEMENT = (
    "CIC-IDS-2018 DoS and DDoS only. PortScan is absent from the dataset and "
    "is not evaluated or claimed. This is a scoped external comparison, not a "
    "general volumetric/scanning validation."
)


# ---------------------------------------------------------------------------
# Loading and split
# ---------------------------------------------------------------------------
def _cic2018_files(directory: str) -> list[str]:
    files = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"no CSV files in {directory}")
    return files


def load_cic2018(
    directory: str,
    chunksize: int = 250_000,
    max_rows: int | None = None,
) -> dict[str, Any]:
    """Load CIC-IDS-2018, keep Benign/DoS/DDoS, and deduplicate.

    Deduplication uses the complete feature row, matching the external-data
    audit. Group hashes are the same feature hashes, so duplicate groups never
    cross partitions.
    """
    started = time.time()
    files = _cic2018_files(directory)
    matrix_parts: list[np.ndarray] = []
    hash_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    raw_rows = kept_rows = header_rows = 0
    seen = 0

    for path in files:
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk.columns = [
                str(column).strip().lstrip("\ufeff") for column in chunk.columns
            ]
            raw_rows += len(chunk)
            duration = pd.to_numeric(chunk.get("Flow Duration"), errors="coerce")
            if duration is None:
                continue
            valid = duration.notna()
            header_rows += int((~valid).sum())
            chunk = chunk.loc[valid]
            if chunk.empty:
                continue

            labels = chunk["Label"] if "Label" in chunk.columns else pd.Series(
                [""] * len(chunk), index=chunk.index
            )
            families = np.asarray(
                [cic2018_family(value) for value in labels], dtype=object
            )
            keep = np.isin(
                families, np.asarray((NEGATIVE_FAMILY, *POSITIVE_FAMILIES), dtype=object)
            )
            if not np.any(keep):
                continue
            chunk = chunk.loc[keep]
            families = families[keep]
            kept_rows += len(chunk)

            frame = cic2018_feature_frame(chunk)
            features, _ = _extract_features(frame)
            matrix = np.column_stack(
                [features[name] for name in TIER_A_FEATURES]
            ).astype(np.float32)
            feature_hashes = _full_feature_hashes(
                chunk,
                exclude=(*CIC_PII_COLUMNS, *CIC_METADATA_COLUMNS),
            )
            family_codes = np.asarray(
                [
                    0 if name == NEGATIVE_FAMILY else POSITIVE_FAMILIES.index(name) + 1
                    for name in families
                ],
                dtype=np.int8,
            )

            matrix_parts.append(matrix)
            hash_parts.append(feature_hashes)
            family_parts.append(family_codes)
            seen += len(chunk)
            if max_rows is not None and seen >= max_rows:
                break
        if max_rows is not None and seen >= max_rows:
            break

    if not matrix_parts:
        raise RuntimeError("no CIC-IDS-2018 rows survived the label/feature filter")

    matrix = np.concatenate(matrix_parts)
    hashes = np.concatenate(hash_parts)
    family_codes = np.concatenate(family_parts)
    del matrix_parts, hash_parts, family_parts
    gc.collect()

    _, unique_index = np.unique(hashes, return_index=True)
    unique_index.sort()
    matrix = matrix[unique_index]
    hashes = hashes[unique_index]
    family_codes = family_codes[unique_index]
    del unique_index
    gc.collect()

    family_names = np.asarray(
        [NEGATIVE_FAMILY, *POSITIVE_FAMILIES], dtype=object
    )
    return {
        "matrix": matrix,
        "group_hashes": hashes,
        "family_codes": family_codes,
        "family_names": family_names,
        "truth": (family_codes > 0).astype(np.int8),
        "rows": int(len(family_codes)),
        "raw_rows": int(raw_rows),
        "header_rows": int(header_rows),
        "rows_kept_before_dedup": int(kept_rows),
        "duplicate_rows": int(kept_rows - len(family_codes)),
        "files": [os.path.basename(path) for path in files],
        "elapsed_seconds": round(time.time() - started, 2),
    }


def _extract_features(frame: pd.DataFrame) -> tuple[dict[str, np.ndarray], dict[str, int]]:
    """Import the frozen Tier A extractor lazily to keep import time low."""
    from scripts.rule_baselines import extract_tier_a

    return extract_tier_a(frame)


def group_split(group_hashes: np.ndarray) -> np.ndarray:
    """Assign complete duplicate groups to 70/15/15 by stable hash bucket."""
    buckets = (group_hashes % 100).astype(np.int16)
    return np.where(buckets < 70, 0, np.where(buckets < 85, 1, 2)).astype(np.int8)


def partition_counts(
    partition: np.ndarray, family_codes: np.ndarray, family_names: np.ndarray
) -> dict[str, dict[str, int]]:
    names = {0: "train", 1: "validation", 2: "test"}
    result: dict[str, dict[str, int]] = {name: {} for name in names.values()}
    keep = partition >= 0
    part = partition[keep].astype(np.int64)
    codes = family_codes[keep].astype(np.int64)
    combo = part * len(family_names) + codes
    values, counts = np.unique(combo, return_counts=True)
    for value, count in zip(values, counts):
        part_code, family_code = divmod(int(value), len(family_names))
        result[names[part_code]][str(family_names[family_code])] = int(count)
    return result


def coverage_gate(
    counts: dict[str, dict[str, int]],
    required: Iterable[str] = POSITIVE_FAMILIES,
) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for family in required:
        row = {name: int(counts[name].get(family, 0)) for name in counts}
        row["required"] = True
        row["pass"] = all(row[name] >= 1 for name in counts)
        rows[family] = row
    missing = [family for family in required if not rows[family]["pass"]]
    train_families = {f for f in required if counts["train"].get(f, 0) > 0}
    validation_families = {f for f in required if counts["validation"].get(f, 0) > 0}
    test_families = {f for f in required if counts["test"].get(f, 0) > 0}
    return {
        "families": rows,
        "missing_required": missing,
        "train_validation_overlap": sorted(train_families & validation_families),
        "validation_test_overlap": sorted(validation_families & test_families),
        "overall_pass": not missing,
        "portscan_present": False,
        "portscan_note": (
            "The external-data audit found zero PortScan rows in CIC-IDS-2018. "
            "The loader keeps Benign/DoS/DDoS only."
        ),
        "reason": (
            "DoS and DDoS are present in train, validation, and test, and the "
            "validation/test family sets overlap. PortScan is absent from the "
            "dataset and is outside this scoped claim."
            if not missing
            else f"Required families absent from at least one partition: {missing}."
        ),
    }


def stratified_train_sample(
    partition: np.ndarray,
    truth: np.ndarray,
    family_codes: np.ndarray,
    cap: int,
    seed: int,
) -> np.ndarray:
    """Cap the training partition with a deterministic random sample.

    The cap is a compute constraint, not a protocol change. Validation and
    test are always scored in full.
    """
    train_index = np.flatnonzero(partition == 0)
    if cap >= train_index.size:
        return train_index
    rng = np.random.default_rng(seed)
    return np.sort(rng.choice(train_index, size=cap, replace=False))


# ---------------------------------------------------------------------------
# Rule features and model fitting
# ---------------------------------------------------------------------------
def rule_feature_dict(matrix: np.ndarray) -> dict[str, np.ndarray]:
    """Rebuild the Tier A rule inputs from the 12-column feature matrix."""
    fwd = matrix[:, TIER_A_FEATURES.index("total_fwd_packets")].astype(np.float64)
    bwd = matrix[:, TIER_A_FEATURES.index("total_backward_packets")].astype(np.float64)
    syn = matrix[:, TIER_A_FEATURES.index("syn_flag_count")].astype(np.float64)
    total_packets = fwd + bwd
    syn_ratio = np.divide(
        syn,
        total_packets,
        out=np.zeros_like(syn),
        where=total_packets > 0.0,
    )
    return {
        "flow_bytes_s": matrix[:, TIER_A_FEATURES.index("flow_bytes_s")].astype(
            np.float64
        ),
        "flow_packets_s": matrix[:, TIER_A_FEATURES.index("flow_packets_s")].astype(
            np.float64
        ),
        "total_packets": total_packets,
        "syn_ratio": np.clip(syn_ratio, 0.0, 1.0),
    }


def fit_models(
    matrix: np.ndarray,
    truth: np.ndarray,
    train_index: np.ndarray,
    validation_index: np.ndarray,
    seed: int,
) -> dict[str, Any]:
    x_train = matrix[train_index]
    y_train = truth[train_index]
    x_validation = matrix[validation_index]

    lr = make_pipeline(
        StandardScaler(),
        LogisticRegression(
            max_iter=2_000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=seed,
        ),
    )
    lr.fit(x_train, y_train)
    lr_scores = lr.predict_proba(x_validation)[:, 1]

    rf = RandomForestClassifier(
        n_estimators=100,
        random_state=seed,
        n_jobs=-1,
        class_weight="balanced_subsample",
        min_samples_leaf=5,
    )
    rf.fit(x_train, y_train)
    rf_scores = rf.predict_proba(x_validation)[:, 1]

    benign_train = x_train[y_train == 0]
    isolation = IsolationForest(
        n_estimators=200,
        random_state=seed,
        n_jobs=-1,
        max_samples=min(256, len(benign_train)),
    )
    isolation.fit(benign_train)
    isolation_scores = -isolation.score_samples(x_validation)

    return {
        "logistic_regression": {"model": lr, "validation_scores": lr_scores},
        "random_forest": {"model": rf, "validation_scores": rf_scores},
        "isolation_forest": {
            "model": isolation,
            "validation_scores": isolation_scores,
        },
    }


def score_models(models: dict[str, Any], matrix: np.ndarray) -> dict[str, np.ndarray]:
    scores: dict[str, np.ndarray] = {}
    for name, entry in models.items():
        model = entry["model"]
        if name == "isolation_forest":
            scores[name] = -model.score_samples(matrix)
        else:
            scores[name] = model.predict_proba(matrix)[:, 1]
    return scores


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def expected_calibration_error(
    truth: np.ndarray, scores: np.ndarray, bins: int = ECE_BINS
) -> float:
    truth = np.asarray(truth, dtype=np.float64)
    scores = np.asarray(scores, dtype=np.float64)
    edges = np.linspace(0.0, 1.0, bins + 1)
    index = np.clip(np.digitize(scores, edges) - 1, 0, bins - 1)
    ece = 0.0
    for bucket in range(bins):
        mask = index == bucket
        if not np.any(mask):
            continue
        ece += (
            mask.mean()
            * abs(float(truth[mask].mean()) - float(scores[mask].mean()))
        )
    return float(ece)


def evaluate_scores(
    scores: np.ndarray,
    family_names: np.ndarray,
    threshold: float,
    prevalences: Iterable[float],
    bootstrap_draws: int,
    seed: int,
    probabilistic: bool = True,
) -> dict[str, Any]:
    scores = np.asarray(scores, dtype=np.float64)
    labels = np.asarray(family_names, dtype=object)
    truth = (labels != NEGATIVE_FAMILY).astype(np.int8)
    counts = confusion_counts(scores, truth, threshold)
    positives = counts["true_positives"] + counts["false_negatives"]
    negatives = counts["false_positives"] + counts["true_negatives"]
    tpr = counts["true_positives"] / positives if positives else None
    fpr = counts["false_positives"] / negatives if negatives else None
    alerts = counts["true_positives"] + counts["false_positives"]

    recall_ci = [None, None]
    if positives:
        low, high = wilson_interval(counts["true_positives"], positives)
        recall_ci = [_finite_or_none(low), _finite_or_none(high)]
    fpr_ci = [None, None]
    if negatives:
        if counts["false_positives"] == 0:
            fpr_ci = [0.0, _finite_or_none(clopper_pearson_upper(0, negatives))]
        else:
            low, high = wilson_interval(counts["false_positives"], negatives)
            fpr_ci = [_finite_or_none(low), _finite_or_none(high)]

    per_family: dict[str, dict[str, Any]] = {}
    for family in POSITIVE_FAMILIES:
        mask = labels == family
        support = int(mask.sum())
        if support == 0:
            continue
        family_alerts = int((scores[mask] > threshold).sum())
        low, high = wilson_interval(family_alerts, support)
        per_family[family] = {
            "support": support,
            "alerts": family_alerts,
            "recall": _finite_or_none(family_alerts / support),
            "recall_ci95": [_finite_or_none(low), _finite_or_none(high)],
        }

    prevalence_rows = []
    bootstrap = (
        bootstrap_prevalence(
            counts["true_positives"],
            counts["false_positives"],
            positives,
            negatives,
            prevalences,
            bootstrap_draws,
            seed,
        )
        if positives and negatives
        else {
            float(p): {"ppv_ci95": [None, None], "alerts_per_10k_ci95": [None, None]}
            for p in prevalences
        }
    )
    for prevalence in prevalences:
        p = float(prevalence)
        row_tpr = tpr if tpr is not None else 0.0
        row_fpr = fpr if fpr is not None else 0.0
        prevalence_rows.append(
            {
                "p": p,
                "ppv": _finite_or_none(ppv_at_prevalence(row_tpr, row_fpr, p)),
                "ppv_ci95": bootstrap[p]["ppv_ci95"],
                "alerts_per_10k": _finite_or_none(
                    alerts_per_10k(row_tpr, row_fpr, p)
                ),
                "alerts_per_10k_ci95": bootstrap[p]["alerts_per_10k_ci95"],
                "break_even_per_flow": _finite_or_none(
                    break_even_per_flow(row_tpr, row_fpr, p)
                ),
            }
        )

    roc_auc = pr_auc = None
    if truth.size and np.unique(truth).size == 2:
        roc_auc = _finite_or_none(roc_auc_score(truth, scores))
        pr_auc = _finite_or_none(average_precision_score(truth, scores))

    if probabilistic:
        brier = _finite_or_none(brier_score_loss(truth, scores))
        ece = _finite_or_none(expected_calibration_error(truth, scores))
    else:
        brier = None
        ece = None

    return {
        "threshold": float(threshold),
        "comparison": ">",
        "alerts": int(alerts),
        "alerts_per_10k": _finite_or_none(10_000.0 * alerts / scores.size)
        if scores.size
        else None,
        "counts": counts,
        "positives": int(positives),
        "negatives": int(negatives),
        "recall": _finite_or_none(tpr),
        "recall_ci95": recall_ci,
        "fpr": _finite_or_none(fpr),
        "fpr_ci95": fpr_ci,
        "precision_at_benchmark": _finite_or_none(
            counts["true_positives"] / alerts
        )
        if alerts
        else None,
        "benchmark_prevalence": _finite_or_none(positives / (positives + negatives))
        if positives + negatives
        else None,
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "brier": brier,
        "ece_10_bins": ece,
        "prevalence": prevalence_rows,
        "per_family_recall": per_family,
    }


def mcnemar_exact(
    predictions_a: np.ndarray,
    predictions_b: np.ndarray,
    truth: np.ndarray,
) -> dict[str, Any]:
    """Exact McNemar on identical flows."""
    correct_a = predictions_a == truth
    correct_b = predictions_b == truth
    b = int(np.sum(correct_a & ~correct_b))
    c = int(np.sum(~correct_a & correct_b))
    if b + c == 0:
        p_value = 1.0
    else:
        p_value = float(binomtest(b, b + c, 0.5).pvalue)
    return {"b": b, "c": c, "p_value": p_value}


def holm_adjust(p_values: list[float]) -> list[float]:
    """Holm-Bonferroni adjusted p-values."""
    m = len(p_values)
    order = np.argsort(p_values)
    adjusted = np.zeros(m, dtype=np.float64)
    running = 0.0
    for rank, index in enumerate(order):
        value = min(1.0, (m - rank) * p_values[index])
        running = max(running, value)
        adjusted[index] = running
    return adjusted.tolist()


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def _pct(value: float | None) -> str:
    return "—" if value is None else f"{100.0 * value:.2f}%"


def _num(value: float | None, digits: int = 4) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def render_report(payload: dict[str, Any]) -> str:
    split = payload["split"]
    gate = payload["coverage_gate"]
    results = payload["results"]
    lines = [
        "# P2B Scoped External Comparison (CIC-IDS-2018 DoS/DDoS)",
        "",
        f"**Status:** {payload['status']}.",
        f"**Scope:** {SCOPE_STATEMENT}",
        f"**Date:** {payload['date']}.",
        f"**Artifact:** [`p2b_scoped_external.json`](p2b_scoped_external.json).",
        "**Script:** [`../scripts/p2b_scoped_external.py`](../scripts/p2b_scoped_external.py).",
        "",
        "## 1. Amendment",
        "",
        "The preregistered P2B protocol uses the CIC-IDS-2017 day split. That split",
        "cannot fit a supervised head: Monday–Tuesday has zero volumetric/scanning",
        "positives, and the Wednesday validation families are disjoint from the",
        "Friday test families. The approved amendment is an A4-scoped external run:",
        "train, validate, and test on a leakage-safe group split of CIC-IDS-2018 for",
        "DoS and DDoS only. PortScan is absent from the dataset and is not claimed.",
        "",
        "## 2. Split",
        "",
        "| Partition | Rows | DoS | DDoS | Benign |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for name in ("train", "validation", "test"):
        row = split["counts"][name]
        lines.append(
            f"| {name.title()} | {split['partition_rows'][name]:,} | "
            f"{row.get('DoS', 0):,} | {row.get('DDoS', 0):,} | "
            f"{row.get('Benign', 0):,} |"
        )
    lines += [
        "",
        f"Group split: `{split['method']}`.",
        "",
        "**Coverage gate:** "
        + ("**PASS**" if gate["overall_pass"] else "**FAIL**")
        + f". {gate['reason']}",
        "",
        "| Family | Train | Validation | Test | Pass |",
        "| --- | ---: | ---: | ---: | :---: |",
    ]
    for family, row in gate["families"].items():
        lines.append(
            f"| {family} | {row['train']:,} | {row['validation']:,} | "
            f"{row['test']:,} | {'yes' if row['pass'] else 'no'} |"
        )
    lines += [
        "",
        "PortScan is **absent** from CIC-IDS-2018. No scan-detection claim is made.",
        "",
        "## 3. Protocol",
        "",
        "| Item | Value |",
        "| --- | --- |",
        f"| Seeds | {', '.join(str(seed) for seed in payload['seeds'])} |",
        f"| Budgets | {', '.join(str(budget) for budget in payload['budgets'])} alerts / 10k |",
        f"| Training cap | {payload['train_cap']:,} rows (validation/test scored in full) |",
        f"| Threshold partition | validation only |",
        f"| Test partition | held out; one pass |",
        "",
        "## 4. Results at 100 alerts / 10k",
        "",
        "| Method | Seed | Recall | FPR | PPV @ benchmark | ROC-AUC | AP | Brier | ECE |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    rows = [
        row
        for row in results
        if row["budget_per_10k"] == 100
    ]
    rows.sort(key=lambda row: (-(row["recall"] or 0.0), row["method"], row["seed"]))
    for row in rows:
        lines.append(
            f"| {row['method']} | {row['seed']} | {_pct(row['recall'])} | "
            f"{_pct(row['fpr'])} | {_pct(row['precision_at_benchmark'])} | "
            f"{_num(row['roc_auc'])} | {_num(row['pr_auc'])} | "
            f"{_num(row['brier'])} | {_num(row['ece_10_bins'])} |"
        )
    lines += [
        "",
        "## 5. Per-family recall at 100 alerts / 10k",
        "",
        "| Method | Seed | DoS recall | DDoS recall |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in rows:
        dos = row["per_family_recall"].get("DoS", {})
        ddos = row["per_family_recall"].get("DDoS", {})
        lines.append(
            f"| {row['method']} | {row['seed']} | "
            f"{_pct(dos.get('recall'))} | {_pct(ddos.get('recall'))} |"
        )
    lines += [
        "",
        "## 6. McNemar: Random Forest vs the best validation rule",
        "",
        "The comparison rule is selected on validation only. The test labels never",
        "influence the choice. Holm adjustment covers the two budgets and three",
        "families (six tests).",
        "",
        "| Budget | Family | Rule | RF recall | Rule recall | b | c | p | Holm p |",
        "| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload["mcnemar"]:
        lines.append(
            f"| {row['budget_per_10k']} | {row['family']} | {row['rule']} | "
            f"{_pct(row['rf_recall'])} | {_pct(row['rule_recall'])} | "
            f"{row['b']} | {row['c']} | {_num(row['p_value'])} | "
            f"{_num(row['holm_p_value'])} |"
        )
    lines += [
        "",
        "## 7. Reading",
        "",
        payload["conclusion"],
        "",
        "## 8. What does not change",
        "",
        "- Serving artifact and threshold: unchanged.",
        "- P2B remains a **scoped external** result, not a general P2B pass.",
        "- PortScan and scan detection remain out of scope.",
        "- Detection and SaaS scores are unchanged.",
        "",
        "## 9. Reproduction",
        "",
        "```bash",
        "venv/Scripts/python.exe scripts/p2b_scoped_external.py \\",
        '  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete"',
        "venv/Scripts/python.exe -m pytest tests/test_p2b_scoped_external.py -q",
        "```",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
def run(
    cic_dir: str,
    seeds: Iterable[int] = DEFAULT_SEEDS,
    budgets: Iterable[int] = BUDGETS,
    train_cap: int = TRAIN_CAP,
    max_rows: int | None = None,
    output: str = RESULTS_JSON,
    report: str = REPORT,
    save_model: bool = True,
) -> dict[str, Any]:
    seeds = tuple(int(seed) for seed in seeds)
    budgets = tuple(int(budget) for budget in budgets)
    data = load_cic2018(cic_dir, max_rows=max_rows)
    partition = group_split(data["group_hashes"])
    counts = partition_counts(partition, data["family_codes"], data["family_names"])
    gate = coverage_gate(counts)
    if not gate["overall_pass"]:
        raise RuntimeError(f"scoped coverage gate failed: {gate['reason']}")

    train_index = stratified_train_sample(
        partition, data["truth"], data["family_codes"], train_cap, seed=42
    )
    validation_index = np.flatnonzero(partition == 1)
    test_index = np.flatnonzero(partition == 2)

    validation_rule_features = rule_feature_dict(data["matrix"][validation_index])
    test_rule_features = rule_feature_dict(data["matrix"][test_index])
    normalization = fit_rule_normalization(validation_rule_features)
    validation_rule_scores = build_rule_scores(
        validation_rule_features, normalization
    )
    test_rule_scores = build_rule_scores(test_rule_features, normalization)
    rule_names = list(validation_rule_scores)
    test_labels = data["family_names"][data["family_codes"][test_index]]

    results: list[dict[str, Any]] = []
    model_artifacts: dict[str, Any] = {}
    rf_test_scores: np.ndarray | None = None

    # Rules: deterministic, so one row per budget.
    for budget in budgets:
        for rule_name in rule_names:
            selected = select_budget_threshold(
                validation_rule_scores[rule_name], budget
            )
            evaluation = evaluate_scores(
                test_rule_scores[rule_name],
                test_labels,
                selected["threshold"],
                PREVALENCES,
                BOOTSTRAP_DRAWS,
                seed=20261113,
                probabilistic=False,
            )
            results.append(
                {
                    "method": rule_name,
                    "family": "all",
                    "seed": 0,
                    "budget_per_10k": budget,
                    "validation_threshold": selected,
                    **evaluation,
                }
            )

    # Supervised and unsupervised models: one fit per seed, thresholds per budget.
    for seed in seeds:
        models = fit_models(
            data["matrix"],
            data["truth"],
            train_index,
            validation_index,
            seed,
        )
        test_scores = score_models(models, data["matrix"][test_index])
        if seed == seeds[0]:
            rf_test_scores = test_scores["random_forest"]
        for method, scores in test_scores.items():
            for budget in budgets:
                selected = select_budget_threshold(
                    models[method]["validation_scores"], budget
                )
                evaluation = evaluate_scores(
                    scores,
                    test_labels,
                    selected["threshold"],
                    PREVALENCES,
                    BOOTSTRAP_DRAWS,
                    seed=seed,
                    probabilistic=method != "isolation_forest",
                )
                results.append(
                    {
                        "method": method,
                        "family": "all",
                        "seed": seed,
                        "budget_per_10k": budget,
                        "validation_threshold": selected,
                        **evaluation,
                    }
                )
        if seed == seeds[0] and save_model:
            model_artifacts = _save_model_bundle(
                models["random_forest"]["model"],
                seed,
                budgets,
                models["random_forest"]["validation_scores"],
            )

    if rf_test_scores is None:
        raise RuntimeError("the first seed did not produce Random Forest scores")
    mcnemar = _mcnemar_table(
        results,
        data,
        test_labels,
        test_rule_scores,
        rf_test_scores,
        seeds[0],
        budgets,
    )
    conclusion = _conclusion(results)

    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "status": "scoped external result",
        "date": time.strftime("%Y-%m-%d"),
        "scope": SCOPE_STATEMENT,
        "dataset": {
            "name": "CIC-IDS-2018",
            "directory": cic_dir,
            "files": data["files"],
            "raw_rows": data["raw_rows"],
            "rows_kept_before_dedup": data["rows_kept_before_dedup"],
            "unique_rows": data["rows"],
            "duplicate_rows": data["duplicate_rows"],
            "header_rows": data["header_rows"],
        },
        "schema": schema_payload(),
        "seeds": list(seeds),
        "budgets": list(budgets),
        "train_cap": int(train_cap),
        "split": {
            "method": (
                "group_hash_split: complete-feature hash mod 100; "
                "buckets 0-69 train, 70-84 validation, 85-99 test"
            ),
            "counts": counts,
            "partition_rows": {
                name: int(np.sum(partition == code))
                for name, code in (("train", 0), ("validation", 1), ("test", 2))
            },
        },
        "coverage_gate": gate,
        "results": results,
        "mcnemar": mcnemar,
        "conclusion": conclusion,
        "model_artifact": model_artifacts,
        "blocked": [
            "PortScan is absent from CIC-IDS-2018; no scan claim is made.",
            "The CIC-IDS-2017 day-split P2B comparison remains blocked.",
            "This is a scoped external result, not a general P2B pass.",
        ],
        "notes": [
            "Thresholds are selected on validation only.",
            "Test is evaluated once with the frozen validation threshold.",
            "The serving artifact, registry row, and threshold are untouched.",
        ],
    }

    os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    if report:
        with open(report, "w", encoding="utf-8") as handle:
            handle.write(render_report(payload))
            handle.write("\n")
    return payload


def _save_model_bundle(
    model: RandomForestClassifier,
    seed: int,
    budgets: Iterable[int],
    validation_scores: np.ndarray,
) -> dict[str, Any]:
    thresholds = {
        f"{budget}_per_10k": select_budget_threshold(validation_scores, budget)
        for budget in budgets
    }
    encoder = LabelEncoder().fit(["BENIGN", "ATTACK"])
    bundle = {
        "pipeline": model,
        "feature_names": list(TIER_A_FEATURES),
        "label_encoder": encoder,
        "task": "binary_attack",
        "attack_threshold": thresholds[f"{max(budgets)}_per_10k"]["threshold"],
        "threshold_comparison": ">",
        "thresholds": thresholds,
        "schema_sha256": feature_schema_sha256(TIER_A_FEATURES),
        "schema_version": feature_schema_version(TIER_A_FEATURES),
        "training_split": "cic2018_group_hash_70_15_15",
        "scope": "CIC-IDS-2018 DoS/DDoS only; PortScan absent",
        "seed": seed,
    }
    joblib.dump(bundle, MODEL_BUNDLE)
    manifest = {
        "artifact_version": ARTIFACT_VERSION,
        "model_type": "rf",
        "task": "binary_attack",
        "seed": seed,
        "split_mode": "group_hash",
        "scope": bundle["scope"],
        "model_file": os.path.basename(MODEL_BUNDLE),
        "model_sha256": _sha256_file(MODEL_BUNDLE),
        "schema": schema_payload(),
        "feature_count": len(TIER_A_FEATURES),
        "features": list(TIER_A_FEATURES),
        "thresholds": thresholds,
        "threshold_comparison": ">",
        "serving_registry_unchanged": True,
        "python_version": sys.version.split()[0],
        "scikit_learn_version": __import__("sklearn").__version__,
    }
    with open(MODEL_MANIFEST, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, allow_nan=False)
        handle.write("\n")
    return {
        "model_file": os.path.basename(MODEL_BUNDLE),
        "manifest_file": os.path.basename(MODEL_MANIFEST),
        "model_sha256": manifest["model_sha256"],
        "scope": bundle["scope"],
        "serving_registry_unchanged": True,
    }


def _mcnemar_table(
    results: list[dict[str, Any]],
    data: dict[str, Any],
    test_labels: np.ndarray,
    test_rule_scores: dict[str, np.ndarray],
    rf_test_scores: np.ndarray,
    seed: int,
    budgets: Iterable[int],
) -> list[dict[str, Any]]:
    """Compare RF seed 42 against the best validation rule at each budget."""
    rf_rows = {
        row["budget_per_10k"]: row
        for row in results
        if row["method"] == "random_forest" and row["seed"] == seed
    }
    rule_rows = {
        (row["budget_per_10k"], row["method"]): row
        for row in results
        if row["seed"] == 0 and row["family"] == "all"
    }
    test_truth = (test_labels != NEGATIVE_FAMILY).astype(np.int8)
    rows: list[dict[str, Any]] = []
    for budget in budgets:
        candidates = [
            (name, rule_rows[(budget, name)])
            for name in test_rule_scores
        ]
        best_name, best_row = max(
            candidates,
            key=lambda item: (
                item[1]["recall"] if item[1]["recall"] is not None else -1.0,
                -(item[1]["fpr"] if item[1]["fpr"] is not None else 1.0),
            ),
        )
        rf_threshold = rf_rows[budget]["threshold"]
        rule_threshold = best_row["threshold"]
        rf_pred = rf_test_scores > rf_threshold
        rule_pred = test_rule_scores[best_name] > rule_threshold
        for family in (*POSITIVE_FAMILIES, "all"):
            if family == "all":
                mask = np.ones(test_truth.size, dtype=bool)
            else:
                mask = test_labels == family
            stats = mcnemar_exact(rf_pred[mask], rule_pred[mask], test_truth[mask])
            rows.append(
                {
                    "budget_per_10k": int(budget),
                    "family": family,
                    "rule": best_name,
                    "rf_recall": rf_rows[budget]["per_family_recall"]
                    .get(family, {})
                    .get("recall")
                    if family != "all"
                    else rf_rows[budget]["recall"],
                    "rule_recall": best_row["per_family_recall"]
                    .get(family, {})
                    .get("recall")
                    if family != "all"
                    else best_row["recall"],
                    **stats,
                }
            )
    adjusted = holm_adjust([row["p_value"] for row in rows])
    for row, value in zip(rows, adjusted):
        row["holm_p_value"] = value
    return rows


def _conclusion(results: list[dict[str, Any]]) -> str:
    at_100 = [
        row
        for row in results
        if row["budget_per_10k"] == 100 and row["seed"] in (0, 42)
    ]
    if not at_100:
        return "No results were produced."
    best = max(
        at_100,
        key=lambda row: (
            row["recall"] if row["recall"] is not None else -1.0,
            -(row["fpr"] if row["fpr"] is not None else 1.0),
        ),
    )
    rf = next(
        (row for row in at_100 if row["method"] == "random_forest" and row["seed"] == 42),
        None,
    )
    if rf is None:
        return "The Random Forest seed-42 result is missing; no comparison is claimed."
    if best["method"] == "random_forest":
        return (
            "At 100 alerts per 10,000 flows, Random Forest seed 42 has the highest "
            f"test recall ({_pct(rf['recall'])}) at FPR {_pct(rf['fpr'])}. This is a "
            "scoped CIC-IDS-2018 DoS/DDoS result, not a PortScan or general "
            "volumetric/scanning claim."
        )
    return (
        f"At 100 alerts per 10,000 flows, the best method is `{best['method']}` "
        f"with recall {_pct(best['recall'])} at FPR {_pct(best['fpr'])}. "
        f"Random Forest seed 42 reaches recall {_pct(rf['recall'])} at FPR "
        f"{_pct(rf['fpr'])}. The supervised comparison is therefore negative or "
        "mixed; it is reported as-is and not tuned on test. This is a scoped "
        "CIC-IDS-2018 DoS/DDoS result, not a PortScan or general claim."
    )


def _parse_int_list(value: str) -> list[int]:
    return [int(part.strip()) for part in value.split(",") if part.strip()]


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cic-dir", default=DEFAULT_CIC_DIR)
    parser.add_argument("--seeds", default=",".join(str(s) for s in DEFAULT_SEEDS))
    parser.add_argument("--budgets", default=",".join(str(b) for b in BUDGETS))
    parser.add_argument("--train-cap", type=int, default=TRAIN_CAP)
    parser.add_argument("--max-rows", type=int, default=None)
    parser.add_argument("--output", default=RESULTS_JSON)
    parser.add_argument("--report", default=REPORT)
    parser.add_argument("--no-model", action="store_true")
    args = parser.parse_args(argv)

    run(
        cic_dir=args.cic_dir,
        seeds=_parse_int_list(args.seeds),
        budgets=_parse_int_list(args.budgets),
        train_cap=args.train_cap,
        max_rows=args.max_rows,
        output=args.output,
        report=args.report,
        save_model=not args.no_model,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
