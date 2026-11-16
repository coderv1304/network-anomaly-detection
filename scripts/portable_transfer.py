#!/usr/bin/env python
"""P3B portable-ratio cross-dataset transfer experiment.

This is a **new research candidate**, not a replacement for the frozen P3
artifact. It answers one question: if the Tier A inputs are reduced to bounded
ratios and log-scaled per-packet quantities, does CIC-IDS-2017 -> external
transfer improve over the frozen raw-scale Tier A baseline?

The transform is in ``training/portable_features.py`` and is fixed before any
external label is scored. Thresholds are selected on the CIC-IDS-2017
validation partition only. The external rank-budget table is reported as a
secondary, label-free diagnostic, exactly as in P3.

Example:
    venv/Scripts/python.exe scripts/portable_transfer.py \
        --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \
        --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import sys
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.cross_dataset_transfer import (  # noqa: E402
    CIC2018_FAMILY_CODES,
    CIC_METADATA_COLUMNS,
    CIC_PII_COLUMNS,
    SERVING_ARTIFACT,
    SERVING_SHA256,
    TIER_A_FEATURES,
    UNSW_FAMILY_CODES,
    _full_feature_hashes,
    cic2018_feature_frame,
    external_budget_threshold,
    external_label,
    load_cic2017,
    metrics_at_threshold,
    ranking_metrics,
    shift_table,
    stratified_group_split,
    tie_aware_metrics,
    unsw_feature_frame,
)
from scripts.rule_baselines import (  # noqa: E402
    _sha256_file,
    select_budget_threshold,
)
from training.model_registry import register_model  # noqa: E402
from training.portable_features import (  # noqa: E402
    PORTABLE_FEATURE_NAMES,
    portable_matrix,
    portable_matrix_from_tier_a,
    schema_payload as portable_schema,
)

SEED = 42
BUDGETS = (10, 100)
MODEL_ID = "netshield-flow-portable"
MODEL_VERSION = "portable-ratio-v1-group-seed42"
MODEL_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_portable_ratio_seed42.pkl"
)
MANIFEST_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_manifest_rf_portable_ratio_seed42.json"
)
RESULTS_JSON = os.path.join(PROJECT_ROOT, "docs", "portable_transfer_results.json")
REPORT = os.path.join(PROJECT_ROOT, "docs", "PORTABLE_TRANSFER.md")
REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "registry", "registry.json")
BASELINE_RESULTS = os.path.join(PROJECT_ROOT, "docs", "cross_dataset_results.json")
ARTIFACT_VERSION = "portable-ratio-transfer-v1"

CIC_FAMILIES = ("Benign", "DoS", "DDoS", "PortScan", "Excluded")
UNSW_FAMILIES = ("Normal", "DoS", "Reconnaissance", "Excluded")

LIMITS = [
    "This run trains on the original CIC-IDS-2017 Kaggle export. The DistriNet-corrected CIC-IDS-2017 CSVs are used by a separate strict-policy in-distribution sensitivity (docs/CORRECTED_LABEL_SENSITIVITY.md), not by this external-transfer artifact.",
    "The portable transform removes raw magnitudes, not every dataset artifact. Flow timeout, packet capture point, and label policy still differ.",
    "Average precision is prevalence-sensitive. The P3 baseline and this candidate are comparable only when both are evaluated on the same external stream in a full run.",
    "The external rank-budget table is transductive and is a diagnostic, not a deployable threshold.",
    "CIC-IDS-2018 covers DoS/DDoS only; PortScan is absent. UNSW-NB15 covers DoS/Reconnaissance only.",
    "The serving artifact, the frozen Tier A report, and all product claims are unchanged.",
]


# ---------------------------------------------------------------------------
# Data adapters
# ---------------------------------------------------------------------------
def _portable_from_tier_a_values(
    fwd_packets: np.ndarray,
    bwd_packets: np.ndarray,
    fwd_bytes: np.ndarray,
    bwd_bytes: np.ndarray,
) -> np.ndarray:
    return portable_matrix(fwd_packets, bwd_packets, fwd_bytes, bwd_bytes)


def _cic2017_portable(data: dict[str, Any]) -> dict[str, Any]:
    """Convert the frozen loader's Tier A matrix to the portable schema."""
    matrix = portable_matrix_from_tier_a(data["matrix"], TIER_A_FEATURES)
    return {
        "matrix": matrix,
        "truth": data["truth"],
        "families": data["families"],
        "group_hashes": data["group_hashes"],
        "repairs": data["repairs"],
        "rows": data["rows"],
        "elapsed_seconds": data["elapsed_seconds"],
    }


def iter_cic2018_portable(
    directory: str,
    pipeline: Any,
    benign_index: int,
    chunksize: int = 250_000,
    max_rows_per_file: int | None = None,
) -> dict[str, Any]:
    files = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"no CSV files in {directory}")

    feature_parts: list[np.ndarray] = []
    hash_parts: list[np.ndarray] = []
    truth_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    raw_rows = kept_rows = header_rows = 0

    for path in files:
        rows_in_file = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk.columns = [
                str(column).strip().lstrip("\ufeff") for column in chunk.columns
            ]
            if max_rows_per_file is not None:
                remaining = max_rows_per_file - rows_in_file
                if remaining <= 0:
                    break
                chunk = chunk.head(remaining)
            raw_rows += len(chunk)
            rows_in_file += len(chunk)
            duration = pd.to_numeric(chunk.get("Flow Duration"), errors="coerce")
            if duration is None:
                continue
            valid = duration.notna()
            header_rows += int((~valid).sum())
            chunk = chunk.loc[valid]
            if chunk.empty:
                continue

            labels = (
                chunk["Label"]
                if "Label" in chunk.columns
                else pd.Series([""] * len(chunk), index=chunk.index)
            )
            roles = np.asarray(
                [external_label(value, "cic_ids_2018") for value in labels],
                dtype=np.int8,
            )
            keep = roles >= 0
            if not np.any(keep):
                continue
            chunk = chunk.loc[keep]
            roles = roles[keep]
            kept_rows += len(chunk)

            frame = cic2018_feature_frame(chunk)
            from scripts.rule_baselines import extract_tier_a  # local import for clarity

            features, _ = extract_tier_a(frame)
            matrix = _portable_from_tier_a_values(
                features["total_fwd_packets"],
                features["total_backward_packets"],
                features["total_length_of_fwd_packets"],
                features["total_length_of_bwd_packets"],
            )

            families = np.asarray(
                [cic2018_family(value) or "Excluded" for value in chunk["Label"]],
                dtype=object,
            )
            family_parts.append(
                np.asarray(
                    [CIC2018_FAMILY_CODES.get(name, 4) for name in families],
                    dtype=np.int8,
                )
            )
            feature_hashes = _full_feature_hashes(
                chunk, exclude=(*CIC_PII_COLUMNS, *CIC_METADATA_COLUMNS)
            )
            feature_parts.append(matrix)
            hash_parts.append(feature_hashes)
            truth_parts.append(roles)
        if max_rows_per_file is not None and rows_in_file >= max_rows_per_file:
            continue

    if not feature_parts:
        raise RuntimeError("no CIC-IDS-2018 rows survived the label/feature filter")

    matrix = np.concatenate(feature_parts)
    hashes = np.concatenate(hash_parts)
    truth = np.concatenate(truth_parts)
    family_codes = np.concatenate(family_parts)
    del feature_parts, hash_parts, truth_parts, family_parts
    gc.collect()

    _, unique_index = np.unique(hashes, return_index=True)
    unique_index.sort()
    matrix = matrix[unique_index]
    truth = truth[unique_index]
    family_codes = family_codes[unique_index]
    scores = 1.0 - pipeline.predict_proba(matrix)[:, benign_index]
    return {
        "dataset": "cic_ids_2018",
        "files": [os.path.basename(path) for path in files],
        "raw_rows": int(raw_rows),
        "header_rows": int(header_rows),
        "rows_kept_before_dedup": int(kept_rows),
        "unique_rows": int(len(truth)),
        "duplicate_rows": int(kept_rows - len(truth)),
        "scores": scores,
        "truth": truth,
        "family_codes": family_codes,
        "matrix": matrix,
        "families": CIC_FAMILIES,
        "available_features": list(PORTABLE_FEATURE_NAMES),
        "comparability": "Full 8/8 portable inputs; no imputation.",
    }


def load_unsw_portable(directory: str, pipeline: Any, benign_index: int) -> dict[str, Any]:
    path = os.path.join(directory, "unsw_test_official.csv")
    frame = pd.read_csv(path, low_memory=False)
    frame.columns = [str(column).strip().lstrip("\ufeff") for column in frame.columns]
    raw_rows = int(len(frame))

    roles = np.asarray(
        [external_label(value, "unsw_nb15") for value in frame["attack_cat"]],
        dtype=np.int8,
    )
    keep = roles >= 0
    frame = frame.loc[keep].reset_index(drop=True)
    roles = roles[keep]
    kept_rows = int(len(frame))

    raw = unsw_feature_frame(frame)
    matrix = portable_matrix_from_tier_a(raw, raw.columns)
    families = frame["attack_cat"].astype(str).to_numpy()
    family_codes = np.asarray(
        [UNSW_FAMILY_CODES.get(name, 3) for name in families], dtype=np.int8
    )
    feature_hashes = _full_feature_hashes(
        frame,
        exclude=("id", "attack_cat", "label", "__hash", "__partition"),
    )
    _, unique_index = np.unique(feature_hashes, return_index=True)
    unique_index.sort()
    matrix = matrix[unique_index]
    roles = roles[unique_index]
    family_codes = family_codes[unique_index]
    scores = 1.0 - pipeline.predict_proba(matrix)[:, benign_index]
    return {
        "dataset": "unsw_nb15",
        "files": [os.path.basename(path)],
        "raw_rows": raw_rows,
        "header_rows": 0,
        "rows_kept_before_dedup": kept_rows,
        "unique_rows": int(len(roles)),
        "duplicate_rows": kept_rows - int(len(roles)),
        "scores": scores,
        "truth": roles,
        "family_codes": family_codes,
        "matrix": matrix,
        "families": UNSW_FAMILIES,
        "available_features": list(PORTABLE_FEATURE_NAMES),
        "comparability": (
            "Full portable schema; UNSW-NB15 lacks max-packet and flag columns, "
            "but the ratio-only schema does not use them."
        ),
    }


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------
def train_portable(data: dict[str, Any]) -> dict[str, Any]:
    split = stratified_group_split(data["group_hashes"], data["families"])
    partition = split["partition"]
    train_mask = partition == 0
    validation_mask = partition == 1
    test_mask = partition == 2

    from scripts.cross_dataset_transfer import coverage_gate, partition_counts

    counts = partition_counts(partition, data["families"])
    gate = coverage_gate(counts)
    if not gate["overall_pass"]:
        raise RuntimeError(f"training split fails the coverage gate: {gate['reason']}")

    classifier = RandomForestClassifier(
        n_estimators=200,
        random_state=SEED,
        n_jobs=-1,
        class_weight=None,
    )
    classifier.fit(data["matrix"][train_mask], data["truth"][train_mask])
    benign_index = int(np.flatnonzero(classifier.classes_ == 0)[0])

    validation_scores = 1.0 - classifier.predict_proba(
        data["matrix"][validation_mask]
    )[:, benign_index]
    thresholds = {}
    for budget in BUDGETS:
        selected = select_budget_threshold(validation_scores, budget)
        thresholds[f"{budget}_per_10k"] = selected

    bundle = {
        "pipeline": classifier,
        "feature_names": list(PORTABLE_FEATURE_NAMES),
        "feature_set": "portable_ratio",
        "feature_schema_sha256": portable_schema()["sha256"],
        "task": "binary_attack",
        "classes": ["BENIGN", "ATTACK"],
        "benign_class_index": benign_index,
        "attack_threshold": thresholds["100_per_10k"]["threshold"],
        "thresholds": thresholds,
        "threshold_comparison": ">",
        "training_split": "stratified_group_seed42_not_p2b",
        "seed": SEED,
        "serving_artifact_untouched": True,
    }
    joblib.dump(bundle, MODEL_PATH)

    manifest = {
        "artifact_version": ARTIFACT_VERSION,
        "model_type": "rf",
        "task": "binary_attack",
        "seed": SEED,
        "split_mode": "stratified_group",
        "model_file": os.path.basename(MODEL_PATH),
        "model_sha256": _sha256_file(MODEL_PATH),
        "schema": portable_schema(),
        "feature_count": len(PORTABLE_FEATURE_NAMES),
        "features": list(PORTABLE_FEATURE_NAMES),
        "thresholds": thresholds,
        "threshold_comparison": ">",
        "training": {
            "rows": data["rows"],
            "partitions": counts,
            "coverage_gate": gate,
            "split": {key: value for key, value in split.items() if key != "partition"},
            "repairs": dict(data["repairs"]),
            "not_p2b": True,
        },
        "python_version": sys.version.split()[0],
        "scikit_learn_version": __import__("sklearn").__version__,
    }
    with open(MANIFEST_PATH, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, allow_nan=False)
        handle.write("\n")

    _register(manifest)
    return {
        "manifest": manifest,
        "partition": partition,
        "split": split,
        "counts": counts,
        "gate": gate,
        "train_mask": train_mask,
        "validation_mask": validation_mask,
        "test_mask": test_mask,
        "reference": data["matrix"][train_mask],
        "test_scores": 1.0 - classifier.predict_proba(data["matrix"][test_mask])[
            :, benign_index
        ],
        "test_truth": data["truth"][test_mask],
    }


def _register(manifest: dict[str, Any]) -> None:
    if not os.path.exists(REGISTRY_PATH):
        return
    try:
        with open(REGISTRY_PATH, encoding="utf-8") as handle:
            registry = json.load(handle)
        versions = registry.get("models", {}).get(MODEL_ID, {}).get("versions", {})
        if MODEL_VERSION in versions:
            return
    except Exception:  # noqa: BLE001 - fall through to registration
        pass
    try:
        register_model(
            REGISTRY_PATH,
            model_id=MODEL_ID,
            version=MODEL_VERSION,
            artifact_path=MODEL_PATH,
            role="research",
            status="candidate",
            threshold_policy={
                "name": "portable_transfer_attack_threshold",
                "threshold": manifest["thresholds"]["100_per_10k"]["threshold"],
                "max_fpr": None,
                "selected_on": "cic_ids_2017_validation_at_100_alerts_per_10k",
                "score": "1 - P(BENIGN)",
                "decision": "attack_score > threshold",
            },
            dataset_sha256={},
            training_config={
                "split_mode": "stratified_group",
                "seed": SEED,
                "n_estimators": 200,
                "feature_set": "portable_ratio",
                "schema_sha256": manifest["schema"]["sha256"],
                "not_p2b": True,
            },
            created_by="p3b-portable-transfer",
            notes=(
                "P3B ratio-only research candidate. It is not the serving model "
                "and does not change the serving artifact or the frozen Tier A "
                "schema. The registry-wide feature_schema_label field is a "
                "constant ('80-feature schema'); the authoritative schema for "
                "this entry is feature_count=8 and feature_schema_sha256="
                f"{manifest['schema']['sha256']}."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - registration must not hide a result
        print(f"warning: registry candidate was not written: {exc}", flush=True)


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def _dataset_payload(
    result: dict[str, Any],
    reference: np.ndarray,
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    scores = result["scores"]
    truth = result["truth"]
    family_codes = result["family_codes"]
    families = result["families"]
    results = {}
    tie_aware = {}
    rank_budget = {}
    for budget, selected in thresholds.items():
        budget_per_10k = int(selected.get("budget_per_10k", budget.split("_")[0]))
        results[budget] = metrics_at_threshold(
            scores, truth, family_codes, families, selected["threshold"]
        )
        tie_aware[budget] = tie_aware_metrics(
            scores,
            truth,
            family_codes,
            families,
            selected["threshold"],
            budget_per_10k,
        )
        rank_budget[budget] = tie_aware_metrics(
            scores,
            truth,
            family_codes,
            families,
            external_budget_threshold(scores, budget_per_10k),
            budget_per_10k,
        )
    ranking = ranking_metrics(scores, truth)
    return {
        "name": result["dataset"],
        "files": result["files"],
        "raw_rows": result["raw_rows"],
        "header_rows": result["header_rows"],
        "unique_rows": result["unique_rows"],
        "duplicate_rows": result["duplicate_rows"],
        "prevalence": results["100_per_10k"]["prevalence"],
        "results": results,
        "tie_aware": tie_aware,
        "rank_budget": rank_budget,
        "ranking": ranking,
        "per_family": results["100_per_10k"]["per_family"],
        "rank_budget_per_family": rank_budget["100_per_10k"]["per_family"],
        "tie_diagnostics": {
            "threshold": tie_aware["100_per_10k"]["threshold"],
            "tie_count": tie_aware["100_per_10k"]["tie_count"],
            "tie_positive_rate": tie_aware["100_per_10k"]["tie_positive_rate"],
            "max_score": tie_aware["100_per_10k"]["max_score"],
            "strict_alerts_at_100_per_10k": results["100_per_10k"]["tp"]
            + results["100_per_10k"]["fp"],
        },
        "comparability": result["comparability"],
        "shift": shift_table(
            reference,
            result["matrix"],
            PORTABLE_FEATURE_NAMES,
            result["available_features"],
        ),
    }


def _baseline() -> dict[str, Any]:
    if not os.path.exists(BASELINE_RESULTS):
        return {}
    with open(BASELINE_RESULTS, encoding="utf-8") as handle:
        payload = json.load(handle)
    summary = {}
    for dataset in payload.get("datasets", []):
        summary[dataset["name"]] = {
            "roc_auc": dataset.get("ranking", {}).get("roc_auc"),
            "average_precision": dataset.get("ranking", {}).get("average_precision"),
            "recall_at_100_per_10k": dataset.get("rank_budget", {})
            .get("100_per_10k", {})
            .get("expected_recall"),
            "ppv_at_100_per_10k": dataset.get("rank_budget", {})
            .get("100_per_10k", {})
            .get("expected_ppv"),
        }
    return summary


def _delta(new: float | None, old: float | None) -> str:
    if new is None or old is None:
        return "—"
    return f"{new - old:+.4f}"


def render_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Portable-Ratio Cross-Dataset Transfer (P3B)")
    lines.append("")
    lines.append(f"**Status:** **{payload['status']}**")
    lines.append("**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.")
    lines.append("**Direction:** CIC-IDS-2017 -> external.")
    lines.append("")
    lines.append(
        "This experiment is a **separate research candidate**. It does not modify "
        "the serving artifact, the frozen Tier A report, or the P3 registry row."
    )
    lines.append("")
    lines.append("## 1. What changed")
    lines.append("")
    lines.append(
        "The P3 transfer model consumed the 12 Tier A columns directly, including "
        "raw duration, packet counts, byte counts, and packet rates. Those columns "
        "are portable in availability but not in distribution: CICFlowMeter timing "
        "and capture-speed artifacts change their scale across datasets."
    )
    lines.append("")
    lines.append(
        "This candidate consumes eight bounded ratios and log-scaled per-packet "
        "quantities derived from the same inputs:"
    )
    lines.append("")
    for feature in PORTABLE_FEATURE_NAMES:
        lines.append(f"- `{feature}`")
    lines.append("")
    lines.append(
        "The transform has no fitted parameters and does not use duration, flags, "
        "packet-length maxima, IP addresses, ports, or labels."
    )
    lines.append("")
    lines.append("## 2. Freeze")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Portable schema version | `{payload['schema']['version']}` |")
    lines.append(f"| Portable features | {payload['schema']['count']} |")
    lines.append(f"| Schema hash | `{payload['schema']['sha256']}` |")
    lines.append(f"| Transfer model SHA-256 | `{payload['model_sha256']}` |")
    lines.append(f"| Serving model SHA-256 | `{payload['serving_sha256']}` |")
    lines.append("| Training split | stratified group, 70/15/15, seed 42 |")
    lines.append("")
    lines.append("## 3. Before / after")
    lines.append("")
    lines.append(
        "The baseline column is the frozen P3 Tier A result from "
        "`docs/cross_dataset_results.json`. The candidate column is the portable "
        "ratio model. Both use the same CIC-IDS-2017 group split, the same external "
        "deduplication, and the same validation-only threshold policy."
    )
    if payload.get("sample_limit_per_file"):
        lines.append("")
        lines.append(
            f"> **Partial run.** At most {payload['sample_limit_per_file']:,} rows "
            "per CIC-IDS-2018 file were read, so the candidate's external rows, "
            "prevalence, and metrics are **not comparable** to the full P3 "
            "baseline. The deltas below are development diagnostics only."
        )
    lines.append("")
    lines.append("| Dataset | Metric | P3 Tier A | Portable ratio | Delta |")
    lines.append("| --- | --- | ---: | ---: | ---: |")
    for dataset in payload["datasets"]:
        name = dataset["name"]
        old = payload["baseline"].get(name, {})
        new = dataset
        for label, new_value, old_value in (
            ("ROC-AUC", new["ranking"]["roc_auc"], old.get("roc_auc")),
            (
                "Average precision",
                new["ranking"]["average_precision"],
                old.get("average_precision"),
            ),
            (
                "Recall @ 100/10k (rank budget)",
                new["rank_budget"]["100_per_10k"]["expected_recall"],
                old.get("recall_at_100_per_10k"),
            ),
            (
                "PPV @ 100/10k (rank budget)",
                new["rank_budget"]["100_per_10k"]["expected_ppv"],
                old.get("ppv_at_100_per_10k"),
            ),
        ):
            lines.append(
                f"| {name} | {label} | {_num(old_value)} | {_num(new_value)} | "
                f"{_delta(new_value, old_value)} |"
            )
    lines.append("")
    lines.append("## 4. Portable model in-distribution check")
    lines.append("")
    lines.append("| Partition | Rows | ROC-AUC | Average precision |")
    lines.append("| --- | ---: | ---: | ---: |")
    for row in payload["in_distribution"]:
        lines.append(
            f"| {row['partition']} | {row['rows']:,} | {_num(row['roc_auc'])} | "
            f"{_num(row['average_precision'])} |"
        )
    lines.append("")
    lines.append("## 5. External results")
    lines.append("")
    saturated = [
        budget
        for budget, selected in payload["thresholds"].items()
        if float(selected["threshold"]) >= 1.0 - 1e-12
    ]
    if saturated:
        lines.append(
            "> **Saturated operating point.** The validation-selected threshold for "
            f"{', '.join(f'`{budget}`' for budget in saturated)} is `1.000000`. "
            "Scores are compared with `>`, so a threshold at the maximum possible "
            "score emits zero strict alerts by construction. That is not a measured "
            "zero false-positive rate, and it is not a deployable operating point. "
            "The rank-budget tables below are the usable ranking diagnostic."
        )
        lines.append("")
    lines.append(
        "Prevalence and PPV are reported at each dataset's own prevalence. They are "
        "**not comparable across datasets**."
    )
    lines.append("")
    for dataset in payload["datasets"]:
        lines.append(f"### {dataset['name']}")
        lines.append("")
        lines.append(
            f"Rows after dedup: **{dataset['unique_rows']:,}**; prevalence: "
            f"**{_pct(dataset['prevalence'])}**."
        )
        lines.append("")
        lines.append("| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for budget, row in dataset["results"].items():
            lines.append(
                f"| {budget} | {row['tp'] + row['fp']:,} | {row['tp']:,} | "
                f"{row['fp']:,} | {_pct(row['recall'])} | {_pct(row['fpr'])} | "
                f"{_pct(row['ppv'])} | {_pct(row['ppv_at_1_percent_prevalence'])} |"
            )
        lines.append("")
        diagnostics = dataset["tie_diagnostics"]
        lines.append(
            f"**Frozen-threshold diagnostic:** threshold "
            f"`{diagnostics['threshold']:.6f}`; maximum external score "
            f"`{_num(diagnostics['max_score'])}`; strict alerts "
            f"**{diagnostics['strict_alerts_at_100_per_10k']:,}**."
        )
        lines.append("")
        lines.append(
            "The rank-budget table below is a secondary, label-free diagnostic. It "
            "picks the external score quantile that spends the budget on the "
            "evaluated stream itself."
        )
        lines.append("")
        lines.append("| Budget | Alerts | TP | FP | Recall | FPR | PPV | PPV @ 1% |")
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for budget, row in dataset["rank_budget"].items():
            lines.append(
                f"| {budget} | {row['expected_alerts']:,.0f} | "
                f"{row['expected_tp']:,.0f} | {row['expected_fp']:,.0f} | "
                f"{_pct(row['expected_recall'])} | {_pct(row['expected_fpr'])} | "
                f"{_pct(row['expected_ppv'])} | "
                f"{_pct(row['ppv_at_1_percent_prevalence'])} |"
            )
        lines.append("")
        lines.append(f"**Comparability:** {dataset['comparability']}")
        lines.append("")
        lines.append("**Covariate shift (PSI / KS):**")
        lines.append("")
        lines.append("| Feature | PSI | KS | Status |")
        lines.append("| --- | ---: | ---: | --- |")
        for feature, row in dataset["shift"].items():
            lines.append(
                f"| `{feature}` | {_num(row['psi'])} | {_num(row['ks'])} | "
                f"{row['status']} |"
            )
        lines.append("")
    lines.append("## 6. Interpretation")
    lines.append("")
    lines.append(payload["interpretation"])
    lines.append("")
    lines.append("## 7. What this does not prove")
    lines.append("")
    for item in payload["limits"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## 8. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/portable_transfer.py \\")
    lines.append('  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \\')
    lines.append('  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"')
    lines.append("venv/Scripts/python.exe -m pytest tests/test_portable_features.py -q")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.4%}"


def _num(value: float | None) -> str:
    return "—" if value is None else f"{value:.4f}"


def _interpret(
    datasets: list[dict[str, Any]],
    baseline: dict[str, Any],
    thresholds: dict[str, Any] | None = None,
) -> str:
    parts = []
    improved_ap: list[str] = []
    improved_roc: list[str] = []
    degraded_roc: list[str] = []
    weakest_name = None
    weakest_ap = None
    weakest_prevalence = None
    weakest_gap = None
    for dataset in datasets:
        name = dataset["name"]
        old = baseline.get(name, {})
        old_ap = old.get("average_precision")
        new_ap = dataset["ranking"]["average_precision"]
        old_roc = old.get("roc_auc")
        new_roc = dataset["ranking"]["roc_auc"]
        parts.append(
            f"{name}: average precision moved from {_num(old_ap)} to "
            f"{_num(new_ap)} ({_delta(new_ap, old_ap)}); chance-level AP on this "
            f"stream is its prevalence ({_pct(dataset['prevalence'])}). ROC-AUC "
            f"moved from {_num(old_roc)} to {_num(new_roc)} "
            f"({_delta(new_roc, old_roc)})."
        )
        if old_ap is not None and new_ap is not None and new_ap > old_ap:
            improved_ap.append(name)
        if old_roc is not None and new_roc is not None:
            if new_roc > old_roc:
                improved_roc.append(name)
            elif new_roc < old_roc:
                degraded_roc.append(name)
        if new_ap is not None and dataset.get("prevalence") is not None:
            gap = float(new_ap) - float(dataset["prevalence"])
            if weakest_gap is None or gap < weakest_gap:
                weakest_gap = gap
                weakest_name = name
                weakest_ap = float(new_ap)
                weakest_prevalence = float(dataset["prevalence"])

    total = len(datasets)
    if len(improved_ap) == total and len(improved_roc) == total:
        conclusion = (
            "The ratio-only schema improved both average precision and ROC-AUC on "
            "every external dataset in this run. That is evidence that raw-scale "
            "features contributed to the P3 negative transfer, not proof that the "
            "detector is production-ready."
        )
    elif not improved_ap and not improved_roc:
        conclusion = (
            "The ratio-only schema did not improve either ranking metric on either "
            "external dataset. That is a negative result: dropping raw magnitudes "
            "alone is not sufficient, and the remaining shift is likely "
            "label/protocol heterogeneity or the datasets' own artifacts."
        )
    else:
        conclusion = (
            "The result is mixed. Average precision improved on "
            f"{len(improved_ap)} of {total} external datasets "
            f"({', '.join(improved_ap) if improved_ap else 'none'}); ROC-AUC "
            f"improved on {len(improved_roc)} of {total} "
            f"({', '.join(improved_roc) if improved_roc else 'none'}) and degraded "
            f"on {len(degraded_roc)} of {total} "
            f"({', '.join(degraded_roc) if degraded_roc else 'none'}). "
            "That metric split must not be reported as a uniform improvement, and "
            "it does not establish that ratio-only features solve cross-dataset "
            "transfer."
        )
    if weakest_name is not None:
        conclusion += (
            f" The weakest absolute result is {weakest_name}: average precision "
            f"{_num(weakest_ap)} versus prevalence {_pct(weakest_prevalence)} "
            f"({weakest_gap:+.4f}). A small gap above chance is not a deployable "
            "operating point."
        )
    saturated = [
        budget
        for budget, selected in (thresholds or {}).items()
        if float(selected.get("threshold", 0.0)) >= 1.0 - 1e-12
    ]
    if saturated:
        conclusion += (
            " The validation-selected threshold saturated at 1.000000, so the "
            "strict-threshold external alert count is zero by construction and is "
            "not a measured false-positive rate."
        )
    return " ".join(parts) + " " + conclusion


def run(
    cic_dir: str,
    unsw_dir: str,
    output: str = RESULTS_JSON,
    report: str = REPORT,
    max_rows_per_file: int | None = None,
    force_train: bool = False,
) -> dict[str, Any]:
    if _sha256_file(SERVING_ARTIFACT) != SERVING_SHA256:
        raise RuntimeError("serving artifact hash changed; refusing to proceed")

    data = _cic2017_portable(load_cic2017())
    if force_train or not os.path.exists(MODEL_PATH) or not os.path.exists(MANIFEST_PATH):
        trained = train_portable(data)
        manifest = trained["manifest"]
    else:
        manifest = json.load(open(MANIFEST_PATH, encoding="utf-8"))
        if manifest["schema"]["sha256"] != portable_schema()["sha256"]:
            raise RuntimeError("existing portable manifest uses a different schema")
        bundle = joblib.load(MODEL_PATH)
        pipeline = bundle["pipeline"]
        benign_index = int(bundle["benign_class_index"])
        partition = stratified_group_split(
            data["group_hashes"], data["families"]
        )["partition"]
        train_mask = partition == 0
        validation_mask = partition == 1
        test_mask = partition == 2
        trained = {
            "manifest": manifest,
            "partition": partition,
            "train_mask": train_mask,
            "validation_mask": validation_mask,
            "test_mask": test_mask,
            "reference": data["matrix"][train_mask],
            "test_scores": 1.0
            - pipeline.predict_proba(data["matrix"][test_mask])[:, benign_index],
            "test_truth": data["truth"][test_mask],
            "counts": manifest["training"]["partitions"],
            "gate": manifest["training"]["coverage_gate"],
        }

    model_sha256 = _sha256_file(MODEL_PATH)
    if manifest["model_sha256"] != model_sha256:
        raise RuntimeError("portable artifact hash does not match its manifest")

    bundle = joblib.load(MODEL_PATH)
    pipeline = bundle["pipeline"]
    benign_index = int(bundle["benign_class_index"])
    thresholds = bundle["thresholds"]
    reference = data["matrix"][trained["train_mask"]]

    in_distribution = []
    partition = trained["partition"]
    for name, mask in (
        ("train", partition == 0),
        ("validation", partition == 1),
        ("test", partition == 2),
    ):
        scores = 1.0 - pipeline.predict_proba(data["matrix"][mask])[:, benign_index]
        ranking = ranking_metrics(scores, data["truth"][mask])
        in_distribution.append(
            {
                "partition": name,
                "rows": int(mask.sum()),
                "roc_auc": ranking["roc_auc"],
                "average_precision": ranking["average_precision"],
            }
        )

    datasets = []
    datasets.append(
        _dataset_payload(
            iter_cic2018_portable(
                cic_dir,
                pipeline,
                benign_index,
                max_rows_per_file=max_rows_per_file,
            ),
            reference,
            thresholds,
        )
    )
    datasets.append(
        _dataset_payload(
            load_unsw_portable(unsw_dir, pipeline, benign_index),
            reference,
            thresholds,
        )
    )

    baseline = _baseline()
    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "status": "PARTIAL" if max_rows_per_file else "COMPLETE",
        "method": "portable_ratio_cic2017_to_external_transfer",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS."
        ),
        "schema": portable_schema(),
        "model_sha256": model_sha256,
        "model_path": os.path.relpath(MODEL_PATH, PROJECT_ROOT).replace("\\", "/"),
        "serving_sha256": _sha256_file(SERVING_ARTIFACT),
        "serving_untouched": True,
        "training": {
            "split_mode": "stratified_group",
            "seed": SEED,
            "coverage_gate": trained["gate"],
            "partitions": trained["counts"],
            "not_p2b": True,
        },
        "thresholds": thresholds,
        "in_distribution": in_distribution,
        "datasets": datasets,
        "baseline": baseline,
        "sample_limit_per_file": max_rows_per_file,
        "interpretation": _interpret(datasets, baseline, thresholds),
        "limits": list(LIMITS),
    }

    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(render_report(payload))
        handle.write("\n")
    print(f"wrote {output}", flush=True)
    print(f"wrote {report}", flush=True)
    return payload


def cic2018_family(value: Any) -> str | None:
    from scripts.external_dataset_audit import cic2018_family as _family

    return _family(value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cic-dir", required=True)
    parser.add_argument("--unsw-dir", required=True)
    parser.add_argument("--output", default=RESULTS_JSON)
    parser.add_argument("--report", default=REPORT)
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None,
        help="Optional development cap. Omit for the full external evaluation.",
    )
    parser.add_argument("--force-train", action="store_true")
    args = parser.parse_args()
    run(
        cic_dir=args.cic_dir,
        unsw_dir=args.unsw_dir,
        output=args.output,
        report=args.report,
        max_rows_per_file=args.max_rows_per_file,
        force_train=args.force_train,
    )
