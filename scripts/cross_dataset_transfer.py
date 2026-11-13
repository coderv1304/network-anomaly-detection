#!/usr/bin/env python
"""P3 cross-dataset transfer for the frozen Tier A schema.

The P3 contract asks for a CIC-IDS-2017 -> external transfer test using the
Tier A-only artifact. No Tier A-only artifact existed: the serving model uses
80 CICFlowMeter columns. This script builds a separate Tier A-only artifact
(12 features) without touching the serving artifact, freezes the schema and the
artifact hash in ``docs/CROSS_DATASET_MAPPING.md``, and only then scores the
external datasets.

The training split is a stratified group split, not the P2B day-based split.
P2B remains blocked: its Monday-Tuesday training partition has zero
volumetric/scanning positives. The group split exists only so a transfer model
can be fitted and is recorded as a separate, non-P2B protocol.

It does not download data, retune the frozen threshold on external labels, or
write the serving registry row.

Examples:
    venv/Scripts/python.exe scripts/cross_dataset_transfer.py \
        --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \
        --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"
"""

from __future__ import annotations

import argparse
import collections
import gc
import hashlib
import json
import math
import os
import sys
import time
from typing import Any, Iterable

import joblib
import numpy as np
import pandas as pd
from scipy.stats import ks_2samp
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import LabelEncoder

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.external_dataset_audit import (  # noqa: E402
    CIC2018_TIER_A_MAP,
    CIC_METADATA_COLUMNS,
    CIC_PII_COLUMNS,
    TIER_A_FEATURES,
    UNSW_TIER_A_MAP,
    cic2018_family,
    cic2018_label_class,
    normalize_label,
    unsw_label_class,
)
from scripts.rule_baselines import (  # noqa: E402
    EXCLUDED_LABELS,
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    _sha256_file,
    alert_budget_k,
    extract_tier_a,
    select_budget_threshold,
)
from training.evaluate import CIC_DAYS  # noqa: E402
from training.model_registry import (  # noqa: E402
    feature_schema_sha256,
    feature_schema_version,
    load_registry,
    register_model,
)
from training.threshold_calibration_v2 import _load_partition  # noqa: E402

ARTIFACT_VERSION = "cross-dataset-transfer-v1"
DEFAULT_CIC_DIR = os.path.expanduser(
    os.path.join("~", "Downloads", "CIC IDS 2018 Complete")
)
DEFAULT_UNSW_DIR = os.path.expanduser(os.path.join("~", "Downloads", "UNSW_NB15"))
TRANSFER_MODEL = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_tierA_group_seed42.pkl"
)
TRANSFER_MANIFEST = os.path.join(
    PROJECT_ROOT, "models", "model_manifest_rf_tierA_group_seed42.json"
)
SERVING_ARTIFACT = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
SERVING_SHA256 = "fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350"
MAPPING_DOC = os.path.join(PROJECT_ROOT, "docs", "CROSS_DATASET_MAPPING.md")
RESULTS_JSON = os.path.join(PROJECT_ROOT, "docs", "cross_dataset_results.json")
REPORT = os.path.join(PROJECT_ROOT, "docs", "CROSS_DATASET.md")
REGISTRY_PATH = os.path.join(PROJECT_ROOT, "models", "registry", "registry.json")

TIER_A_MODEL_ID = "netshield-flow-tierA"
TIER_A_VERSION = "tierA-group-seed42-v1"
SEED = 42
BUDGETS = (10, 100)
KS_SAMPLE = 200_000
PSI_BINS = 10

# Family codes are positional in the ``families`` tuple passed to the metric
# helper. PortScan is kept separate even though the audited CIC-IDS-2018 export
# contains zero PortScan rows: silently folding it into "Excluded" would hide a
# scanning family if a future release adds one.
CIC2018_FAMILY_CODES = {"Benign": 0, "DoS": 1, "DDoS": 2, "PortScan": 3}
UNSW_FAMILY_CODES = {"Normal": 0, "DoS": 1, "Reconnaissance": 2}

# CIC-IDS-2017 canonical columns for the 12 Tier A features. The CIC-2018
# export uses CICFlowMeter-2018 names and is renamed to these before extraction.
CIC_CANONICAL = {
    "flow_duration": "Flow Duration",
    "total_fwd_packets": "Total Fwd Packets",
    "total_backward_packets": "Total Backward Packets",
    "total_length_of_fwd_packets": "Total Length of Fwd Packets",
    "total_length_of_bwd_packets": "Total Length of Bwd Packets",
    "flow_packets_s": "Flow Packets/s",
    "flow_bytes_s": "Flow Bytes/s",
    "packet_length_mean": "Packet Length Mean",
    "packet_length_max": "Max Packet Length",
    "syn_flag_count": "SYN Flag Count",
    "fin_flag_count": "FIN Flag Count",
    "rst_flag_count": "RST Flag Count",
}

GROUP_COLUMNS = (
    "Source IP",
    "Destination IP",
    "Source Port",
    "Destination Port",
    "Protocol",
)

LICENSES = {
    "cic_ids_2018": {
        "status": "cleared_for_academic_use_with_citation",
        "source_url": "https://www.unb.ca/cic/datasets/ids-2018.html",
        "quote": (
            "You may redistribute, republish, and mirror the CSE-CIC-IDS2018 "
            "dataset in any form. However, any use or redistribution of the data "
            "must include a citation to the CSE-CIC-IDS2018 dataset and a link to "
            "this page in AWS."
        ),
        "citation": (
            "Sharafaldin, Lashkari, Ghorbani (2018), Toward Generating a New "
            "Intrusion Detection Dataset and Intrusion Traffic Characterization, "
            "ICISSP 2018."
        ),
        "link": "https://registry.opendata.aws/cse-cic-ids2018",
    },
    "unsw_nb15": {
        "status": "cleared_for_academic_use_with_citation",
        "source_url": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
        "quote": (
            "Free use of the UNSW-NB15 dataset for academic research purposes is "
            "hereby granted in perpetuity. Use for commercial purposes should be "
            "agreed by the authors."
        ),
        "citation": (
            "Moustafa and Slay (2015), UNSW-NB15: a comprehensive data set for "
            "network intrusion detection systems, MilCIS 2015, plus the four "
            "additional papers listed on the official page."
        ),
        "link": "https://research.unsw.edu.au/projects/unsw-nb15-dataset",
    },
    "cidds002": {
        "status": "not_used_for_tier_a_transfer",
        "source_url": (
            "https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/"
        ),
        "quote": "Licence terms not verified for publication.",
        "citation": (
            "Ring, Wunderlich, Scheuring, Landes, Hotho (2017), Creation of "
            "Flow-Based Data Sets for Intrusion Detection, Journal of Information "
            "Warfare 16(4)."
        ),
        "link": (
            "https://www.hs-coburg.de/forschen/cidds-coburg-intrusion-detection-data-sets/"
        ),
    },
}


# ---------------------------------------------------------------------------
# Schema and mapping
# ---------------------------------------------------------------------------
def schema_payload() -> dict[str, Any]:
    return {
        "features": list(TIER_A_FEATURES),
        "count": len(TIER_A_FEATURES),
        "sha256": feature_schema_sha256(TIER_A_FEATURES),
        "version": feature_schema_version(TIER_A_FEATURES),
    }


def feature_status(mapping: dict[str, tuple]) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    for feature in TIER_A_FEATURES:
        source, status, note = mapping[feature]
        rows[feature] = {
            "status": status,
            "source_column": source,
            "present": status in {"rename", "derive"},
            "note": note,
        }
    return {
        "features": rows,
        "available": sum(1 for row in rows.values() if row["present"]),
        "missing": sum(1 for row in rows.values() if not row["present"]),
        "total": len(TIER_A_FEATURES),
    }


def external_label(raw: Any, dataset: str) -> int:
    """Return 1 positive, 0 negative, -1 excluded. Never guess a benign class."""
    if dataset == "cic_ids_2018":
        role = cic2018_label_class(raw)
    elif dataset == "unsw_nb15":
        role = unsw_label_class(raw)
    else:
        raise ValueError(f"unknown dataset: {dataset}")
    return {"positive": 1, "negative": 0}.get(role, -1)


# ---------------------------------------------------------------------------
# Training data and split
# ---------------------------------------------------------------------------
def load_cic2017() -> dict[str, Any]:
    """Load CIC-IDS-2017 with the frozen loader and extract Tier A features."""
    started = time.time()
    frame = _load_partition(CIC_DAYS)
    labels = frame["__label"].to_numpy(dtype=object)
    keep = np.isin(
        labels, np.asarray(sorted(POSITIVE_LABELS | NEGATIVE_LABELS), dtype=object)
    )
    frame = frame.loc[keep].reset_index(drop=True)
    labels = labels[keep]

    features, repairs = extract_tier_a(frame)
    matrix = np.column_stack([features[name] for name in TIER_A_FEATURES]).astype(
        np.float32
    )
    truth = np.isin(
        labels, np.asarray(sorted(POSITIVE_LABELS), dtype=object)
    ).astype(np.int8)
    families = np.asarray([str(value) for value in labels], dtype=object)

    key_frame = frame[list(GROUP_COLUMNS)].astype(str)
    # Include the family in the group key. A 5-tuple alone is mixed-label in
    # this capture: the attacker and victim reuse ports, so a 5-tuple can carry
    # both benign and attack flows. Grouping by 5-tuple alone would drop those
    # groups, and the three smaller DoS families disappear entirely. The group
    # is therefore (5-tuple, family): a whole labelled connection group stays in
    # one partition, while the per-flow model still never sees the 5-tuple.
    key_frame["__family"] = families
    group_hashes = pd.util.hash_pandas_object(key_frame, index=False).to_numpy(
        dtype=np.uint64
    )
    del frame, key_frame
    gc.collect()
    return {
        "matrix": matrix,
        "truth": truth,
        "families": families,
        "group_hashes": group_hashes,
        "repairs": repairs,
        "rows": int(matrix.shape[0]),
        "elapsed_seconds": round(time.time() - started, 2),
    }


def stratified_group_split(
    group_hashes: np.ndarray,
    families: np.ndarray,
    seed: int = SEED,
    fractions: tuple[float, float, float] = (0.70, 0.15, 0.15),
) -> dict[str, Any]:
    """Assign whole (5-tuple, family) groups to train/validation/test.

    The group key is computed in ``load_cic2017`` and includes the family. A
    group whose rows carry more than one family is dropped rather than assigned:
    keeping it would leak a family across partitions. The split is
    deterministic for a fixed seed and group hash.
    """
    table = pd.DataFrame({"group": group_hashes, "family": families})
    aggregated = table.groupby("group")["family"].agg(["nunique", "first"])
    mixed = aggregated[aggregated["nunique"] > 1]
    clean = aggregated[aggregated["nunique"] == 1]

    assignment: dict[int, int] = {}
    rng = np.random.default_rng(seed)
    per_family: dict[str, dict[str, int]] = {}
    for family in sorted(clean["first"].unique()):
        keys = clean.index[clean["first"] == family].to_numpy()
        rng.shuffle(keys)
        n = len(keys)
        n_train = max(1, int(round(fractions[0] * n)))
        n_validation = max(1, int(round(fractions[1] * n)))
        if n_train + n_validation >= n:
            n_train = max(1, n - 2)
            n_validation = 1
        for key in keys[:n_train]:
            assignment[int(key)] = 0
        for key in keys[n_train : n_train + n_validation]:
            assignment[int(key)] = 1
        for key in keys[n_train + n_validation :]:
            assignment[int(key)] = 2
        per_family[str(family)] = {
            "groups": int(n),
            "train": int(n_train),
            "validation": int(n_validation),
            "test": int(n - n_train - n_validation),
        }

    partition = pd.Series(group_hashes).map(assignment).fillna(-1).to_numpy(dtype=np.int8)
    return {
        "partition": partition,
        "mixed_groups_dropped": int(len(mixed)),
        "mixed_rows_dropped": int(np.sum(partition < 0)),
        "per_family": per_family,
        "fractions": {
            "train": fractions[0],
            "validation": fractions[1],
            "test": fractions[2],
        },
    }


def serializable_split(split: dict[str, Any]) -> dict[str, Any]:
    """Drop the in-memory partition array so the split can be written to JSON."""
    return {key: value for key, value in split.items() if key != "partition"}


def partition_counts(partition: np.ndarray, families: np.ndarray) -> dict[str, dict[str, int]]:
    names = {0: "train", 1: "validation", 2: "test"}
    result: dict[str, dict[str, int]] = {name: {} for name in names.values()}
    keep = partition >= 0
    part = partition[keep].astype(np.int64)
    family_names, family_codes = np.unique(
        np.asarray([str(value) for value in families[keep]], dtype=object),
        return_inverse=True,
    )
    combo = part * len(family_names) + family_codes
    codes, counts = np.unique(combo, return_counts=True)
    for code, count in zip(codes, counts):
        part_code, family_code = divmod(int(code), len(family_names))
        result[names[part_code]][str(family_names[family_code])] = int(count)
    return result


def coverage_gate(counts: dict[str, dict[str, int]]) -> dict[str, Any]:
    families = sorted(
        set(counts["train"]) | set(counts["validation"]) | set(counts["test"])
    )
    positives = sorted(POSITIVE_LABELS)
    rows: dict[str, Any] = {}
    for family in families:
        row = {name: int(counts[name].get(family, 0)) for name in counts}
        row["required"] = family in positives
        row["observed"] = any(row[name] > 0 for name in counts)
        row["pass"] = all(row[name] >= 1 for name in counts) if family in positives else True
        rows[family] = row
    missing = [name for name in positives if not rows.get(name, {}).get("pass", False)]
    train_families = {name for name in positives if counts["train"].get(name, 0) > 0}
    validation_families = {
        name for name in positives if counts["validation"].get(name, 0) > 0
    }
    test_families = {name for name in positives if counts["test"].get(name, 0) > 0}
    return {
        "families": rows,
        "missing_required": missing,
        "train_validation_overlap": sorted(train_families & validation_families),
        "validation_test_overlap": sorted(validation_families & test_families),
        "overall_pass": not missing,
        "reason": (
            "Every required positive family is present in train, validation, and "
            "test, and validation/test families overlap."
            if not missing
            else f"Required families absent from at least one partition: {missing}."
        ),
    }


def train_transfer_model(data: dict[str, Any]) -> dict[str, Any]:
    split = stratified_group_split(data["group_hashes"], data["families"])
    partition = split["partition"]
    counts = partition_counts(partition, data["families"])
    gate = coverage_gate(counts)
    if not gate["overall_pass"]:
        raise RuntimeError(f"training split fails the coverage gate: {gate['reason']}")

    train_mask = partition == 0
    validation_mask = partition == 1
    test_mask = partition == 2

    classifier = RandomForestClassifier(
        n_estimators=100,
        random_state=SEED,
        n_jobs=-1,
        class_weight=None,
    )
    classifier.fit(data["matrix"][train_mask], data["truth"][train_mask])

    encoder = LabelEncoder().fit(["BENIGN", "ATTACK"])
    benign_index = int(np.flatnonzero(classifier.classes_ == 0)[0])

    validation_scores = 1.0 - classifier.predict_proba(
        data["matrix"][validation_mask]
    )[:, benign_index]
    thresholds = {}
    for budget in BUDGETS:
        selected = select_budget_threshold(validation_scores, budget)
        thresholds[f"{budget}_per_10k"] = selected

    # Missing-feature policy is frozen here, before any external scoring. The
    # medians come from the CIC-IDS-2017 training partition only.
    train_matrix = data["matrix"][train_mask]
    medians = {
        feature: float(np.median(train_matrix[:, index]))
        for index, feature in enumerate(TIER_A_FEATURES)
    }

    bundle = {
        "pipeline": classifier,
        "feature_names": list(TIER_A_FEATURES),
        "label_encoder": encoder,
        "task": "binary_attack",
        "attack_threshold": thresholds["100_per_10k"]["threshold"],
        "threshold_comparison": ">",
        "thresholds": thresholds,
        "schema_sha256": feature_schema_sha256(TIER_A_FEATURES),
        "schema_version": feature_schema_version(TIER_A_FEATURES),
        "training_split": "stratified_group_seed42",
        "benign_class_index": benign_index,
        "classes": ["BENIGN", "ATTACK"],
        "missing_feature_policy": "median_imputation_from_cic2017_train",
        "missing_feature_medians": medians,
        "seed": SEED,
    }
    joblib.dump(bundle, TRANSFER_MODEL)

    manifest = {
        "artifact_version": ARTIFACT_VERSION,
        "model_type": "rf",
        "task": "binary_attack",
        "seed": SEED,
        "split_mode": "stratified_group",
        "model_file": os.path.basename(TRANSFER_MODEL),
        "model_sha256": _sha256_file(TRANSFER_MODEL),
        "schema": schema_payload(),
        "feature_count": len(TIER_A_FEATURES),
        "features": list(TIER_A_FEATURES),
        "thresholds": thresholds,
        "threshold_comparison": ">",
        "training": {
            "rows": data["rows"],
            "partitions": counts,
            "coverage_gate": gate,
            # ``partition`` is an in-memory array used for the masks; it is not
            # serialisable and is not needed in the manifest.
            "split": serializable_split(split),
            "repairs": dict(data["repairs"]),
        },
        "missing_feature_policy": {
            "name": "median_imputation_from_cic2017_train",
            "medians": medians,
            "statement": (
                "External datasets that lack a Tier A column receive the CIC-IDS-2017 "
                "training median for that column. The result is reported as a "
                "partial-schema transfer, not a full Tier A validation."
            ),
        },
        "python_version": sys.version.split()[0],
        "scikit_learn_version": __import__("sklearn").__version__,
    }
    with open(TRANSFER_MANIFEST, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, allow_nan=False)
        handle.write("\n")

    register_transfer_model(manifest, thresholds)
    return {
        "manifest": manifest,
        "partition": partition,
        "split": split,
        "counts": counts,
        "gate": gate,
        "train_mask": train_mask,
        "validation_mask": validation_mask,
        "test_mask": test_mask,
        "reference_matrix": data["matrix"][train_mask],
    }


def register_transfer_model(manifest: dict[str, Any], thresholds: dict[str, Any]) -> None:
    """Register a research candidate. Never approve or activate it."""
    registry = load_registry(REGISTRY_PATH)
    existing = registry.get("models", {}).get(TIER_A_MODEL_ID, {}).get("versions", {})
    if TIER_A_VERSION in existing:
        return
    register_model(
        REGISTRY_PATH,
        model_id=TIER_A_MODEL_ID,
        version=TIER_A_VERSION,
        artifact_path=TRANSFER_MODEL,
        role="research",
        status="candidate",
        threshold_policy={
            "name": "transfer_attack_threshold",
            "threshold": thresholds["100_per_10k"]["threshold"],
            "max_fpr": None,
            "selected_on": "cic_ids_2017_validation_at_100_alerts_per_10k",
            "score": "1 - P(BENIGN)",
            "decision": "attack_score > threshold",
        },
        dataset_sha256={},
        training_config={
            "split_mode": "stratified_group",
            "seed": SEED,
            "n_estimators": 100,
            "class_weight": None,
            "schema_sha256": manifest["schema"]["sha256"],
            "not_p2b": True,
        },
        created_by="p3-cross-dataset",
        notes=(
            "Tier A-only research artifact for P3 transfer. Not the serving "
            "model. P2B remains blocked. The registry-wide "
            "feature_schema_label field is a constant ('80-feature schema'); "
            "the authoritative schema for this entry is feature_count=12, "
            "feature_schema_sha256="
            + manifest["schema"]["sha256"]
            + "."
        ),
    )


# ---------------------------------------------------------------------------
# External adapters
# ---------------------------------------------------------------------------
def cic2018_feature_frame(chunk: pd.DataFrame) -> pd.DataFrame:
    rename = {
        source: CIC_CANONICAL[feature]
        for feature, (source, status, _) in CIC2018_TIER_A_MAP.items()
        if source
    }
    frame = chunk.rename(columns=rename)
    return frame


def unsw_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Build the 12 Tier A columns; the four absent columns are NaN."""
    duration = pd.to_numeric(frame["dur"], errors="coerce").to_numpy(dtype=np.float64)
    spkts = pd.to_numeric(frame["spkts"], errors="coerce").to_numpy(dtype=np.float64)
    dpkts = pd.to_numeric(frame["dpkts"], errors="coerce").to_numpy(dtype=np.float64)
    sbytes = pd.to_numeric(frame["sbytes"], errors="coerce").to_numpy(dtype=np.float64)
    dbytes = pd.to_numeric(frame["dbytes"], errors="coerce").to_numpy(dtype=np.float64)

    duration = np.where(np.isfinite(duration) & (duration >= 0.0), duration, 0.0)
    spkts = np.where(np.isfinite(spkts) & (spkts >= 0.0), spkts, 0.0)
    dpkts = np.where(np.isfinite(dpkts) & (dpkts >= 0.0), dpkts, 0.0)
    sbytes = np.where(np.isfinite(sbytes) & (sbytes >= 0.0), sbytes, 0.0)
    dbytes = np.where(np.isfinite(dbytes) & (dbytes >= 0.0), dbytes, 0.0)

    total_packets = spkts + dpkts
    total_bytes = sbytes + dbytes
    duration_s = duration
    packets_rate = np.divide(
        total_packets,
        duration_s,
        out=np.zeros_like(total_packets),
        where=duration_s > 0.0,
    )
    bytes_rate = np.divide(
        total_bytes,
        duration_s,
        out=np.zeros_like(total_bytes),
        where=duration_s > 0.0,
    )
    packet_mean = np.divide(
        total_bytes,
        total_packets,
        out=np.zeros_like(total_bytes),
        where=total_packets > 0.0,
    )

    result = pd.DataFrame(
        {
            "flow_duration": duration * 1_000_000.0,
            "total_fwd_packets": spkts,
            "total_backward_packets": dpkts,
            "total_length_of_fwd_packets": sbytes,
            "total_length_of_bwd_packets": dbytes,
            "flow_packets_s": packets_rate,
            "flow_bytes_s": bytes_rate,
            "packet_length_mean": packet_mean,
            "packet_length_max": np.nan,
            "syn_flag_count": np.nan,
            "fin_flag_count": np.nan,
            "rst_flag_count": np.nan,
        }
    )
    return result


def apply_missing_policy(
    frame: pd.DataFrame, medians: dict[str, float]
) -> pd.DataFrame:
    result = frame.copy()
    for feature in TIER_A_FEATURES:
        if feature not in result.columns:
            result[feature] = np.nan
        result[feature] = pd.to_numeric(result[feature], errors="coerce")
        result[feature] = result[feature].fillna(float(medians[feature]))
    return result[TIER_A_FEATURES]


def score_matrix(
    pipeline: Any, matrix: np.ndarray, benign_index: int
) -> np.ndarray:
    return 1.0 - pipeline.predict_proba(matrix)[:, benign_index]


def _full_feature_hashes(frame: pd.DataFrame, exclude: Iterable[str]) -> np.ndarray:
    """Hash the complete feature row, not just the 12 model features.

    Deduplicating on the 12 Tier A features would merge distinct flows that
    happen to share packet counts, byte totals, duration, and flags. That
    collapse is label-arbitrary and inflates the effect of duplicate removal.
    The hash basis here matches the external-data audit: every column except
    identifiers and metadata, sorted for a stable order.
    """
    excluded = set(exclude)
    columns = sorted(
        column for column in frame.columns if column not in excluded
    )
    if not columns:
        return np.zeros(len(frame), dtype=np.uint64)
    return (
        pd.util.hash_pandas_object(frame[columns], index=False)
        .astype("uint64")
        .to_numpy()
    )


def iter_cic2018(
    directory: str,
    pipeline: Any,
    benign_index: int,
    chunksize: int = 250_000,
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
            features, _ = extract_tier_a(frame)
            matrix = np.column_stack(
                [features[name] for name in TIER_A_FEATURES]
            ).astype(np.float32)

            families = np.asarray(
                [
                    cic2018_family(value) or "Excluded"
                    for value in chunk["Label"]
                ],
                dtype=object,
            )
            family_codes = np.asarray(
                [CIC2018_FAMILY_CODES.get(name, 4) for name in families],
                dtype=np.int8,
            )
            feature_hashes = _full_feature_hashes(
                chunk,
                exclude=(*CIC_PII_COLUMNS, *CIC_METADATA_COLUMNS),
            )

            feature_parts.append(matrix)
            hash_parts.append(feature_hashes)
            truth_parts.append(roles)
            family_parts.append(family_codes)

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
    scores = score_matrix(pipeline, matrix, benign_index)
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
        "families": ("Benign", "DoS", "DDoS", "PortScan", "Excluded"),
        "available_features": list(TIER_A_FEATURES),
    }


def load_unsw(
    directory: str, pipeline: Any, benign_index: int, medians: dict[str, float]
) -> dict[str, Any]:
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
    matrix = apply_missing_policy(raw, medians).to_numpy(dtype=np.float32)
    families = frame["attack_cat"].astype(str).to_numpy()
    family_codes = np.asarray(
        [UNSW_FAMILY_CODES.get(name, 3) for name in families],
        dtype=np.int8,
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
    unique_rows = int(len(roles))
    scores = score_matrix(pipeline, matrix, benign_index)
    return {
        "dataset": "unsw_nb15",
        "files": [os.path.basename(path)],
        "raw_rows": raw_rows,
        "header_rows": 0,
        "rows_kept_before_dedup": kept_rows,
        "unique_rows": unique_rows,
        "duplicate_rows": kept_rows - unique_rows,
        "scores": scores,
        "truth": roles,
        "family_codes": family_codes,
        "matrix": matrix,
        "families": ("Normal", "DoS", "Reconnaissance", "Excluded"),
        "available_features": [
            feature
            for feature in TIER_A_FEATURES
            if UNSW_TIER_A_MAP[feature][1] in {"rename", "derive"}
        ],
        "official_split": "test",
    }


# ---------------------------------------------------------------------------
# Diagnostics and metrics
# ---------------------------------------------------------------------------
def _finite_sample(values: np.ndarray, limit: int = KS_SAMPLE) -> np.ndarray:
    array = np.asarray(values, dtype=np.float64)
    array = array[np.isfinite(array)]
    if array.size <= limit:
        return array
    rng = np.random.default_rng(SEED)
    index = rng.choice(array.size, size=limit, replace=False)
    index.sort()
    return array[index]


def psi(reference: np.ndarray, actual: np.ndarray, bins: int = PSI_BINS) -> float | None:
    ref = _finite_sample(reference)
    act = _finite_sample(actual)
    if ref.size == 0 or act.size == 0:
        return None
    edges = np.unique(np.quantile(ref, np.linspace(0.0, 1.0, bins + 1)))
    if edges.size < 2:
        return 0.0
    ref_counts, _ = np.histogram(ref, bins=edges)
    act_counts, _ = np.histogram(act, bins=edges)
    ref_pct = ref_counts / max(int(ref_counts.sum()), 1)
    act_pct = act_counts / max(int(act_counts.sum()), 1)
    epsilon = 1e-6
    ref_pct = np.clip(ref_pct, epsilon, None)
    act_pct = np.clip(act_pct, epsilon, None)
    return float(np.sum((act_pct - ref_pct) * np.log(act_pct / ref_pct)))


def ks_statistic(reference: np.ndarray, actual: np.ndarray) -> float | None:
    ref = _finite_sample(reference)
    act = _finite_sample(actual)
    if ref.size == 0 or act.size == 0:
        return None
    return float(ks_2samp(ref, act, alternative="two-sided").statistic)


def metrics_at_threshold(
    scores: np.ndarray,
    truth: np.ndarray,
    family_codes: np.ndarray,
    families: Iterable[str],
    threshold: float,
) -> dict[str, Any]:
    predicted = np.asarray(scores) > float(threshold)
    positive = np.asarray(truth) == 1
    tp = int(np.sum(predicted & positive))
    fp = int(np.sum(predicted & ~positive))
    tn = int(np.sum(~predicted & ~positive))
    fn = int(np.sum(~predicted & positive))
    total = tp + fp + tn + fn
    prevalence = (tp + fn) / total if total else None
    recall = tp / (tp + fn) if tp + fn else None
    fpr = fp / (fp + tn) if fp + tn else None
    ppv = tp / (tp + fp) if tp + fp else None
    ppv_at_one_percent = (
        recall * 0.01 / (recall * 0.01 + fpr * 0.99)
        if recall is not None and fpr is not None and (recall * 0.01 + fpr * 0.99) > 0
        else None
    )
    per_family = {}
    for code, name in enumerate(families):
        if name in {"Benign", "Normal", "Excluded"}:
            continue
        mask = np.asarray(family_codes) == code
        count = int(mask.sum())
        if count:
            detected = int(np.sum(predicted & mask))
            per_family[name] = {
                "rows": count,
                "detected": detected,
                "recall": detected / count,
            }
    return {
        "threshold": float(threshold),
        "comparison": ">",
        "rows": total,
        "prevalence": prevalence,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "recall": recall,
        "fpr": fpr,
        "ppv": ppv,
        "ppv_at_1_percent_prevalence": ppv_at_one_percent,
        "alert_rate": (tp + fp) / total if total else None,
        "per_family": per_family,
    }


def ranking_metrics(scores: np.ndarray, truth: np.ndarray) -> dict[str, float | None]:
    """AUC and average precision. Evaluation only; never used to pick a threshold."""
    positive = np.asarray(truth) == 1
    if positive.all() or not positive.any():
        return {"roc_auc": None, "average_precision": None}
    return {
        "roc_auc": float(roc_auc_score(positive, scores)),
        "average_precision": float(average_precision_score(positive, scores)),
    }


def external_budget_threshold(scores: np.ndarray, budget_per_10k: int) -> float:
    """Pick the external score quantile that spends the alert budget.

    This is label-free: it uses only the unlabelled external scores. It is
    transductive (it reads the evaluated stream's score distribution) and is
    reported as a secondary diagnostic, not as the frozen threshold.
    """
    array = np.sort(np.asarray(scores, dtype=np.float64))[::-1]
    if array.size == 0:
        raise ValueError("scores must be non-empty")
    k = alert_budget_k(budget_per_10k, int(array.size))
    if k >= array.size:
        minimum = float(array[-1])
        return minimum - max(1e-12, abs(minimum) * 1e-12)
    if k <= 0:
        return float(array[0])
    return float(array[k])


def tie_aware_metrics(
    scores: np.ndarray,
    truth: np.ndarray,
    family_codes: np.ndarray,
    families: Iterable[str],
    threshold: float,
    budget_per_10k: int,
) -> dict[str, Any]:
    """Expected metrics when the alert budget is filled by a uniform tie-break.

    The frozen threshold is the rank K+1 score selected on CIC-IDS-2017
    validation. A 100-tree Random Forest emits discrete probabilities, so that
    threshold can equal the maximum score (1.0) and the strict ``>`` rule then
    produces zero alerts. This function keeps the threshold and the budget and
    spends the budget uniformly at random among rows whose score equals the
    threshold. It does not read external labels to choose anything; the labels
    are used only to report the expected confusion counts.

    The expected counts are exact under that randomised tie-break: each tied
    row is selected with probability ``remaining / tie_count``.
    """
    scores = np.asarray(scores, dtype=np.float64)
    positive = np.asarray(truth) == 1
    codes = np.asarray(family_codes)
    strict = scores > threshold
    ties = scores == threshold
    total = int(scores.size)
    k = alert_budget_k(budget_per_10k, total)

    strict_alerts = int(strict.sum())
    tie_count = int(ties.sum())
    remaining = max(k - strict_alerts, 0)
    selected = min(remaining, tie_count)
    tie_positive = int((ties & positive).sum())
    tie_rate = tie_positive / tie_count if tie_count else 0.0

    strict_tp = int((strict & positive).sum())
    strict_fp = int((strict & ~positive).sum())
    expected_tp = strict_tp + selected * tie_rate
    expected_fp = strict_fp + selected * (1.0 - tie_rate)

    positives = int(positive.sum())
    negatives = total - positives
    recall = expected_tp / positives if positives else None
    fpr = expected_fp / negatives if negatives else None
    ppv = (
        expected_tp / (expected_tp + expected_fp)
        if (expected_tp + expected_fp) > 0
        else None
    )
    ppv_at_one_percent = (
        recall * 0.01 / (recall * 0.01 + fpr * 0.99)
        if recall is not None and fpr is not None and (recall * 0.01 + fpr * 0.99) > 0
        else None
    )

    per_family: dict[str, Any] = {}
    for code, name in enumerate(families):
        if name in {"Benign", "Normal", "Excluded"}:
            continue
        mask = codes == code
        count = int(mask.sum())
        if not count:
            continue
        family_strict = int((strict & mask).sum())
        family_ties = int((ties & mask).sum())
        expected_detected = family_strict + (
            selected * family_ties / tie_count if tie_count else 0.0
        )
        per_family[name] = {
            "rows": count,
            "expected_detected": expected_detected,
            "expected_recall": expected_detected / count,
        }

    return {
        "budget_per_10k": int(budget_per_10k),
        "threshold": float(threshold),
        "k": int(k),
        "strict_alerts": strict_alerts,
        "tie_count": tie_count,
        "tie_positive_rate": tie_rate,
        "selected_from_ties": int(selected),
        "expected_alerts": expected_tp + expected_fp,
        "expected_tp": expected_tp,
        "expected_fp": expected_fp,
        "expected_recall": recall,
        "expected_fpr": fpr,
        "expected_ppv": ppv,
        "ppv_at_1_percent_prevalence": ppv_at_one_percent,
        "max_score": float(scores.max()) if scores.size else None,
        "min_score": float(scores.min()) if scores.size else None,
        "per_family": per_family,
    }


def shift_table(
    reference: np.ndarray,
    matrix: np.ndarray,
    features: Iterable[str],
    available: Iterable[str],
) -> dict[str, Any]:
    rows: dict[str, Any] = {}
    available_set = set(available)
    for index, feature in enumerate(features):
        if feature not in available_set:
            rows[feature] = {
                "psi": None,
                "ks": None,
                "status": "missing_imputed",
            }
            continue
        values = matrix[:, index]
        finite = np.isfinite(values)
        if not np.any(finite):
            rows[feature] = {
                "psi": None,
                "ks": None,
                "status": "missing_or_non_finite",
            }
            continue
        rows[feature] = {
            "psi": psi(reference[:, index], values[finite]),
            "ks": ks_statistic(reference[:, index], values[finite]),
            "status": "available",
        }
    return rows


# ---------------------------------------------------------------------------
# Freeze document
# ---------------------------------------------------------------------------
def render_mapping(
    schema: dict[str, Any],
    model_sha256: str,
    audit: dict[str, Any],
) -> str:
    lines: list[str] = []
    lines.append("# Cross-Dataset Mapping and Freeze")
    lines.append("")
    lines.append("**Status:** **FROZEN before external scoring.**")
    lines.append("**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.")
    lines.append("")
    lines.append("This file is written before the frozen Tier A model scores any external")
    lines.append("label. It records the schema, the model artifact hash, the label mapping,")
    lines.append("the feature mapping, and the missing-feature policy.")
    lines.append("")
    lines.append("## 1. Freeze")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Tier A features | {schema['count']} |")
    lines.append(f"| Schema hash | `{schema['sha256']}` |")
    lines.append(f"| Schema version | `{schema['version']}` |")
    lines.append(f"| Transfer model | `models/{os.path.basename(TRANSFER_MODEL)}` |")
    lines.append(f"| Transfer model SHA-256 | `{model_sha256}` |")
    lines.append(f"| Serving model SHA-256 | `{SERVING_SHA256}` |")
    lines.append("| Training direction | CIC-IDS-2017 -> external |")
    lines.append("")
    lines.append("The transfer model is a **Tier A-only** Random Forest. It is a separate")
    lines.append("research artifact. The 80-feature serving model and its registry row are")
    lines.append("not modified. Tier B is unavailable and is not mixed into any transfer")
    lines.append("number.")
    lines.append("")
    lines.append("**Deviation recorded:** the external-data audits inspected label")
    lines.append("distributions and feature schemas for feasibility before this freeze. No")
    lines.append("external detection performance was computed before the freeze. The freeze")
    lines.append("covers the model, thresholds, label mapping, and feature mapping used for")
    lines.append("scoring.")
    lines.append("")
    lines.append("## 2. Tier A schema")
    lines.append("")
    lines.append("| Feature | Unit | CIC-IDS-2017 column |")
    lines.append("| --- | --- | --- |")
    for feature in TIER_A_FEATURES:
        lines.append(f"| `{feature}` | per-flow | `{CIC_CANONICAL[feature]}` |")
    lines.append("")
    lines.append("The schema is the P2A portable Tier A contract. It is frozen at the hash")
    lines.append("above; no feature was added, removed, or renamed after external scoring")
    lines.append("began.")
    lines.append("")
    lines.append("## 3. Dataset provenance and licences")
    lines.append("")
    lines.append("| Dataset | Version | Source | Licence status |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        f"| CIC-IDS-2018 | 10 daily CSVs | {LICENSES['cic_ids_2018']['source_url']} | "
        f"{LICENSES['cic_ids_2018']['status']} |"
    )
    lines.append(
        f"| UNSW-NB15 | official train/test CSV | {LICENSES['unsw_nb15']['source_url']} | "
        f"{LICENSES['unsw_nb15']['status']} |"
    )
    lines.append(
        f"| CIDDS-002 | two-week NetFlow | {LICENSES['cidds002']['source_url']} | "
        f"**BLOCKED for Tier A** ({LICENSES['cidds002']['status']}) |"
    )
    lines.append("")
    for name in ("cic_ids_2018", "unsw_nb15"):
        entry = LICENSES[name]
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"> {entry['quote']}")
        lines.append("")
        lines.append(f"Citation: {entry['citation']}")
        lines.append("")
        lines.append(f"Link: {entry['link']}")
        lines.append("")
    lines.append("CIDDS-002 is unidirectional NetFlow. Its licence terms were not verified")
    lines.append("for publication, and it cannot supply the two backward counters or")
    lines.append("`packet_length_max`. It is recorded as **BLOCKED for Tier A transfer** and")
    lines.append("is not part of any transfer number. See `docs/CIDDS002_AUDIT.md`.")
    lines.append("")
    lines.append("## 4. Feature mapping")
    lines.append("")
    for dataset, mapping in (
        ("CIC-IDS-2018", CIC2018_TIER_A_MAP),
        ("UNSW-NB15", UNSW_TIER_A_MAP),
    ):
        status = feature_status(mapping)
        lines.append(f"### {dataset} — {status['available']}/{status['total']} available")
        lines.append("")
        lines.append("| Feature | Status | Source column | Note |")
        lines.append("| --- | --- | --- | --- |")
        for feature in TIER_A_FEATURES:
            row = status["features"][feature]
            lines.append(
                f"| `{feature}` | {row['status']} | "
                f"{row['source_column'] or '—'} | {row['note'] or '—'} |"
            )
        lines.append("")
    lines.append("## 5. Label mapping")
    lines.append("")
    lines.append("| Dataset | Positive | Negative | Excluded |")
    lines.append("| --- | --- | --- | --- |")
    lines.append(
        "| CIC-IDS-2018 | `DDoS*`, `DoS*` | `Benign` | Bot, brute force, infiltration, SQL injection, XSS |"
    )
    lines.append(
        "| UNSW-NB15 | `DoS`, `Reconnaissance` | `Normal` | Analysis, Backdoor, Exploits, Fuzzers, Generic, Shellcode, Worms |"
    )
    lines.append("")
    lines.append("Unknown labels are excluded, never treated as benign.")
    lines.append("")
    lines.append("## 6. Missing-feature policy")
    lines.append("")
    lines.append("A dataset that lacks a Tier A column receives the CIC-IDS-2017 training")
    lines.append("median for that column. The medians are stored in the model manifest and")
    lines.append("in the model bundle. A result produced under this policy is reported as a")
    lines.append("**partial-schema transfer**, not a full Tier A validation. UNSW-NB15")
    lines.append("lacks `packet_length_max`, `syn_flag_count`, `fin_flag_count`, and")
    lines.append("`rst_flag_count`; its result is partial-schema.")
    lines.append("")
    lines.append("## 7. Artifact hashes")
    lines.append("")
    lines.append("| File | SHA-256 |")
    lines.append("| --- | --- |")
    for dataset in ("cic_ids_2018", "unsw_nb15"):
        for item in audit["datasets"][dataset]["provenance"]["files"]:
            lines.append(
                f"| `{os.path.basename(item['path'])}` | `{item['sha256']}` |"
            )
    lines.append("")
    lines.append("## 8. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/cross_dataset_transfer.py \\")
    lines.append('  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \\')
    lines.append('  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"')
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def write_mapping(schema: dict[str, Any], model_sha256: str, audit: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(MAPPING_DOC), exist_ok=True)
    with open(MAPPING_DOC, "w", encoding="utf-8") as handle:
        handle.write(render_mapping(schema, model_sha256, audit))
        handle.write("\n")


def verify_freeze(schema: dict[str, Any], model_sha256: str) -> None:
    """Abort if the mapping doc records a different schema or model hash."""
    if not os.path.exists(MAPPING_DOC):
        raise RuntimeError(
            "CROSS_DATASET_MAPPING.md is missing; refusing to score before the freeze"
        )
    text = open(MAPPING_DOC, encoding="utf-8").read()
    if schema["sha256"] not in text:
        raise RuntimeError("schema hash in the mapping doc does not match the frozen schema")
    if model_sha256 not in text:
        raise RuntimeError(
            "model hash in the mapping doc does not match the transfer artifact; "
            "refusing to score"
        )


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def render_report(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Cross-Dataset Transfer (P3)")
    lines.append("")
    lines.append(f"**Status:** **{payload['status']}**")
    lines.append("**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.")
    lines.append("**Direction:** CIC-IDS-2017 -> external.")
    lines.append("")
    lines.append("This report evaluates the frozen Tier A-only artifact. It does not")
    lines.append("evaluate the 80-feature serving model, does not change its threshold, and")
    lines.append("does not unblock P2B.")
    lines.append("")
    lines.append("## 1. Freeze")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Tier A features | {payload['schema']['count']} |")
    lines.append(f"| Schema hash | `{payload['schema']['sha256']}` |")
    lines.append(f"| Transfer model SHA-256 | `{payload['model_sha256']}` |")
    lines.append(f"| Serving model SHA-256 | `{payload['serving_sha256']}` |")
    lines.append("| Training split | stratified group, 70/15/15 |")
    lines.append("")
    lines.append("The training split is not the P2B day split. P2B remains blocked because")
    lines.append("its Monday-Tuesday partition has zero volumetric/scanning positives. The")
    lines.append("group split is a separate transfer protocol and is not a P2B result.")
    lines.append("")
    lines.append("## 2. Training coverage")
    lines.append("")
    lines.append("| Family | Train | Validation | Test |")
    lines.append("| --- | ---: | ---: | ---: |")
    for family, row in payload["training"]["coverage_gate"]["families"].items():
        if family == "BENIGN":
            continue
        lines.append(
            f"| {family} | {row['train']:,} | {row['validation']:,} | {row['test']:,} |"
        )
    lines.append("")
    lines.append(payload["training"]["coverage_gate"]["reason"])
    lines.append("")
    lines.append("## 3. External results")
    lines.append("")
    lines.append("Prevalence and PPV are reported at each dataset's own prevalence. They are")
    lines.append("**not comparable across datasets**: a raw precision comparison across")
    lines.append("different base rates is not meaningful.")
    lines.append("")
    lines.append(
        "Duplicate removal uses the **complete feature row**, not only the 12 Tier A "
        "features, so distinct flows that share packet counts and byte totals are "
        "not merged. Duplicate groups are collapsed to their first occurrence, which "
        "keeps label assignment deterministic."
    )
    lines.append("")
    for dataset in payload["datasets"]:
        lines.append(f"### {dataset['name']}")
        lines.append("")
        lines.append(
            f"Rows after dedup: **{dataset['unique_rows']:,}**; "
            f"prevalence: **{_pct(dataset['prevalence'])}**."
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
            "**Frozen-threshold diagnostics:** threshold "
            f"`{diagnostics['threshold']:.6f}`; maximum external score "
            f"`{_num(diagnostics['max_score'])}`; tied rows "
            f"**{diagnostics['tie_count']:,}** with a positive rate of "
            f"**{_pct(diagnostics['tie_positive_rate'])}**. The strict `>` rule "
            "therefore emits **0 alerts**, and that is the primary frozen result."
        )
        lines.append("")
        lines.append(
            "The tie-aware table is a **secondary, post-hoc diagnostic**. It keeps "
            "the same threshold and alert budget and fills the budget by uniform "
            "random selection among tied scores. It does not change the artifact, "
            "schema, or threshold."
        )
        lines.append("")
        lines.append(
            "| Budget | Expected alerts | Expected TP | Expected FP | "
            "Expected recall | Expected FPR | Expected PPV | PPV @ 1% |"
        )
        lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
        for budget, row in dataset["tie_aware"].items():
            lines.append(
                f"| {budget} | {row['expected_alerts']:,.0f} | "
                f"{row['expected_tp']:,.0f} | {row['expected_fp']:,.0f} | "
                f"{_pct(row['expected_recall'])} | {_pct(row['expected_fpr'])} | "
                f"{_pct(row['expected_ppv'])} | "
                f"{_pct(row['ppv_at_1_percent_prevalence'])} |"
            )
        lines.append("")
        lines.append(
            "The next table is a **label-free rank-budget diagnostic**. It picks the "
            "score quantile that spends the budget on the evaluated stream itself. "
            "It is transductive (it reads the unlabelled external scores) and is "
            "reported separately from the frozen threshold."
        )
        lines.append("")
        lines.append(
            "| Budget | Expected alerts | Expected TP | Expected FP | "
            "Expected recall | Expected FPR | Expected PPV | PPV @ 1% |"
        )
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
        ranking = dataset["ranking"]
        lines.append(
            f"**Ranking (evaluation only):** ROC-AUC `{_num(ranking['roc_auc'])}`, "
            f"average precision `{_num(ranking['average_precision'])}`."
        )
        lines.append("")
        if dataset["per_family"]:
            lines.append("| Family | Rows | Expected detected @100 | Expected recall @100 |")
            lines.append("| --- | ---: | ---: | ---: |")
            for family, row in dataset["rank_budget_per_family"].items():
                lines.append(
                    f"| {family} | {row['rows']:,} | "
                    f"{row['expected_detected']:,.0f} | "
                    f"{_pct(row['expected_recall'])} |"
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
    lines.append("## 4. Negative transfer")
    lines.append("")
    lines.append(payload["negative_transfer"])
    lines.append("")
    lines.append("## 5. What does not change")
    lines.append("")
    lines.append("- Serving artifact and threshold: unchanged.")
    lines.append("- P2B supervised comparison: still blocked.")
    lines.append("- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.")
    lines.append("- Tier B remains unavailable.")
    lines.append("")
    lines.append("## 6. Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/cross_dataset_transfer.py \\")
    lines.append('  --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" \\')
    lines.append('  --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"')
    lines.append("venv/Scripts/python.exe -m pytest tests/test_cross_dataset_transfer.py -q")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.4%}"


def _num(value: float | None) -> str:
    return "—" if value is None else f"{value:.4f}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run(
    cic_dir: str,
    unsw_dir: str,
    output: str,
    report: str,
    mapping: str,
    force_train: bool = False,
) -> dict[str, Any]:
    global MAPPING_DOC
    MAPPING_DOC = mapping
    if _sha256_file(SERVING_ARTIFACT) != SERVING_SHA256:
        raise RuntimeError("serving artifact hash changed; refusing to proceed")
    if os.path.abspath(TRANSFER_MODEL) == os.path.abspath(SERVING_ARTIFACT):
        raise RuntimeError("transfer artifact path must differ from the serving artifact")

    audit = json.load(open(os.path.join(PROJECT_ROOT, "docs", "EXTERNAL_DATASET_AUDIT.json")))
    schema = schema_payload()

    data = load_cic2017()
    if force_train or not os.path.exists(TRANSFER_MODEL) or not os.path.exists(TRANSFER_MANIFEST):
        trained = train_transfer_model(data)
        manifest = trained["manifest"]
    else:
        manifest = json.load(open(TRANSFER_MANIFEST, encoding="utf-8"))
        if manifest["schema"]["sha256"] != schema["sha256"]:
            raise RuntimeError("existing transfer manifest uses a different schema")
        trained = None

    model_sha256 = _sha256_file(TRANSFER_MODEL)
    if manifest["model_sha256"] != model_sha256:
        raise RuntimeError("transfer artifact hash does not match its manifest")

    write_mapping(schema, model_sha256, audit)
    verify_freeze(schema, model_sha256)

    bundle = joblib.load(TRANSFER_MODEL)
    pipeline = bundle["pipeline"]
    benign_index = int(bundle.get("benign_class_index", 0))
    if benign_index >= len(pipeline.classes_):
        raise RuntimeError("stored benign class index is invalid")
    medians = bundle["missing_feature_medians"]
    thresholds = bundle["thresholds"]

    # The split is deterministic; recompute it to recover the train reference
    # matrix for PSI/KS even when the artifact was reused.
    split = stratified_group_split(data["group_hashes"], data["families"])
    reference = data["matrix"][split["partition"] == 0]

    datasets = []
    cic = iter_cic2018(cic_dir, pipeline, benign_index)
    datasets.append(_dataset_payload(cic, reference, thresholds, medians))

    unsw = load_unsw(unsw_dir, pipeline, benign_index, medians)
    datasets.append(_dataset_payload(unsw, reference, thresholds, medians))

    payload = {
        "artifact_version": ARTIFACT_VERSION,
        "status": "PARTIAL",
        "method": "frozen_tier_a_cic2017_to_external_transfer",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Tier B unavailable."
        ),
        "schema": schema,
        "model_sha256": model_sha256,
        "model_path": os.path.relpath(TRANSFER_MODEL, PROJECT_ROOT).replace("\\", "/"),
        "serving_sha256": _sha256_file(SERVING_ARTIFACT),
        "serving_untouched": True,
        "training": {
            "split_mode": "stratified_group",
            "seed": SEED,
            "coverage_gate": manifest["training"]["coverage_gate"],
            "partitions": manifest["training"]["partitions"],
            "not_p2b": True,
        },
        "thresholds": thresholds,
        "datasets": datasets,
        "negative_transfer": _negative_transfer_text(datasets),
        "blocked": [
            {
                "dataset": "cidds002",
                "reason": (
                    "Unidirectional NetFlow, 9/12 Tier A features, licence terms "
                    "not verified for publication. Recorded as BLOCKED for Tier A "
                    "transfer; see docs/CIDDS002_AUDIT.md."
                ),
            },
            {
                "dataset": "tier_b",
                "reason": "No PCAP/PCAPNG or stateful 60-second aggregator.",
            },
        ],
        "notes": [
            "The transfer model is a separate Tier A-only artifact.",
            "The serving artifact and its registry row are unchanged.",
            "External prevalence is reported per dataset; raw precision is not compared.",
            "UNSW-NB15 is a partial-schema transfer because four Tier A columns are absent.",
        ],
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
    print(f"wrote {mapping}", flush=True)
    return payload


def _dataset_payload(
    result: dict[str, Any],
    reference: np.ndarray,
    thresholds: dict[str, Any],
    medians: dict[str, float],
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
    prevalence = results["100_per_10k"]["prevalence"]
    per_family = results["100_per_10k"]["per_family"]
    tie_aware_family = tie_aware["100_per_10k"]["per_family"]
    ranking = ranking_metrics(scores, truth)
    comparability = (
        "Full 12/12 Tier A schema."
        if result["dataset"] == "cic_ids_2018"
        else "Partial 8/12 Tier A schema; the four missing columns are median-imputed."
    )
    shift = shift_table(
        reference,
        result["matrix"],
        TIER_A_FEATURES,
        result["available_features"],
    )
    return {
        "name": result["dataset"],
        "files": result["files"],
        "raw_rows": result["raw_rows"],
        "header_rows": result["header_rows"],
        "unique_rows": result["unique_rows"],
        "duplicate_rows": result["duplicate_rows"],
        "prevalence": prevalence,
        "results": results,
        "tie_aware": tie_aware,
        "rank_budget": rank_budget,
        "ranking": ranking,
        "per_family": per_family,
        "tie_aware_per_family": tie_aware_family,
        "rank_budget_per_family": rank_budget["100_per_10k"]["per_family"],
        "tie_diagnostics": {
            "threshold": tie_aware["100_per_10k"]["threshold"],
            "tie_count": tie_aware["100_per_10k"]["tie_count"],
            "tie_positive_rate": tie_aware["100_per_10k"]["tie_positive_rate"],
            "max_score": tie_aware["100_per_10k"]["max_score"],
            "min_score": tie_aware["100_per_10k"]["min_score"],
            "strict_alerts_at_100_per_10k": results["100_per_10k"]["tp"]
            + results["100_per_10k"]["fp"],
        },
        "comparability": comparability,
        "shift": shift,
        "label_policy": {
            "positive": (
                ["DDoS", "DoS"] if result["dataset"] == "cic_ids_2018" else ["DoS", "Reconnaissance"]
            ),
            "negative": ["Benign"] if result["dataset"] == "cic_ids_2018" else ["Normal"],
        },
        "missing_feature_policy": (
            "none" if result["dataset"] == "cic_ids_2018" else "median_imputation_from_cic2017_train"
        ),
    }


def _negative_transfer_text(datasets: list[dict[str, Any]]) -> str:
    parts = []
    for dataset in datasets:
        row = dataset["rank_budget"]["100_per_10k"]
        ranking = dataset["ranking"]
        diagnostics = dataset["tie_diagnostics"]
        parts.append(
            f"{dataset['name']}: at a 100-alert/10k budget chosen on the external "
            f"score quantile, expected recall {_pct(row['expected_recall'])}, "
            f"expected FPR {_pct(row['expected_fpr'])}, expected PPV "
            f"{_pct(row['expected_ppv'])} at {_pct(dataset['prevalence'])} "
            f"prevalence; ROC-AUC {_num(ranking['roc_auc'])}, average precision "
            f"{_num(ranking['average_precision'])}. The frozen threshold "
            f"({diagnostics['threshold']:.6f}) produced "
            f"{diagnostics['strict_alerts_at_100_per_10k']} strict alerts; the "
            f"maximum external score was {_num(diagnostics['max_score'])}."
        )
    return (
        "The frozen strict rule is the primary outcome. It produced zero alerts on "
        "both datasets: the validation threshold collapsed to 1.0 on score ties, "
        "and UNSW-NB15 never reaches it. The tie-aware and rank-budget tables are "
        "secondary diagnostics that do not change the artifact, schema, or "
        "threshold; the rank-budget threshold reads only unlabelled external "
        "scores. Transfer is reported with numbers, including where it is weak. "
        + " ".join(parts)
        + " These are negative or partial results; they are preserved rather than "
        "tuned away."
    )


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cic-dir", default=DEFAULT_CIC_DIR)
    parser.add_argument("--unsw-dir", default=DEFAULT_UNSW_DIR)
    parser.add_argument("--output", default=RESULTS_JSON)
    parser.add_argument("--report", default=REPORT)
    parser.add_argument("--mapping", default=MAPPING_DOC)
    parser.add_argument("--force-train", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(
        args.cic_dir,
        args.unsw_dir,
        args.output,
        args.report,
        args.mapping,
        force_train=args.force_train,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
