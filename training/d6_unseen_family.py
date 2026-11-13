#!/usr/bin/env python
"""D6: rare/unseen-family and Botnet experiment.

This script implements the predeclared protocol in
``docs/D6_EXPERIMENT_PROTOCOL.md``.  It is deliberately memory safe: the
development machine has 8 GB of RAM, so the training partition is represented
by a fixed sample (all training attacks + 200k benign rows) and validation/test
scoring is streamed in chunks.

The held-out test partition is read once per arm.  No test label is used to fit
a model, choose a feature, select a threshold, fit calibration, or choose the
hybrid blend weight.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import (  # noqa: E402
    CIC_DAYS,
    evaluate_alert_budgets,
    select_threshold_at_max_fpr,
)

FEATURE_COLS = None  # loaded from models/feature_names.pkl
ENCODINGS = ("utf-8-sig", "cp1252", "latin1")
CHUNK_SIZE = 50_000
TRAIN_BENIGN_SAMPLE = 200_000
TRAIN_SAMPLE_SEED = 42
SEEDS = (42, 43, 44, 45, 46)
TARGET_FPR = 0.01
FAMILY_ORDER = [
    "BENIGN",
    "Bot",
    "DDoS",
    "DoS GoldenEye",
    "DoS Hulk",
    "DoS Slowhttptest",
    "DoS slowloris",
    "Heartbleed",
    "Infiltration",
    "PortScan",
    "Web Attack - Brute Force",
    "Web Attack - Sql Injection",
    "Web Attack - XSS",
]


def normalize_label(value: Any) -> str:
    """Match the normalised labels used by the existing eval cache."""
    text = str(value).strip()
    text = text.replace("\ufffd", "-").replace("�", "-")
    text = text.replace("Web Attack �", "Web Attack -")
    text = " ".join(text.split())
    return text


def read_header(path: str) -> pd.DataFrame:
    for encoding in ENCODINGS:
        try:
            return pd.read_csv(path, nrows=0, encoding=encoding)
        except UnicodeDecodeError:
            continue
    raise UnicodeDecodeError(f"could not decode header for {path}")


def column_mapping(path: str, feature_cols: list[str]) -> tuple[dict[str, str], str]:
    header = read_header(path)
    clean_to_original = {str(column).strip(): column for column in header.columns}
    mapping = {clean_to_original[name]: name for name in feature_cols if name in clean_to_original}
    if "Label" not in clean_to_original:
        raise KeyError(f"Label column not found in {path}")
    mapping[clean_to_original["Label"]] = "Label"
    return mapping, clean_to_original["Label"]


def iter_feature_chunks(
    path: str,
    feature_cols: list[str],
    chunksize: int = CHUNK_SIZE,
    limit_rows: int | None = None,
):
    """Yield ``(X, labels, source_name)`` chunks with clean feature columns."""
    mapping, _ = column_mapping(path, feature_cols)
    usecols = list(mapping)
    last_error = None
    for encoding in ENCODINGS:
        try:
            reader = pd.read_csv(
                path,
                usecols=usecols,
                dtype={column: np.float32 for column in usecols if mapping[column] != "Label"},
                encoding=encoding,
                chunksize=chunksize,
                low_memory=False,
            )
            remaining = limit_rows
            for chunk in reader:
                if remaining is not None:
                    if remaining <= 0:
                        break
                    chunk = chunk.iloc[:remaining]
                    remaining -= len(chunk)
                chunk = chunk.rename(columns=mapping)
                if "Label" not in chunk.columns:
                    raise KeyError(f"Label column missing after rename in {path}")
                labels = chunk.pop("Label")
                for name in feature_cols:
                    if name not in chunk.columns:
                        chunk[name] = np.nan
                X = chunk[feature_cols].astype(np.float32)
                X = X.replace([np.inf, -np.inf], np.nan)
                yield X, labels, os.path.basename(path)
            return
        except UnicodeDecodeError as exc:
            last_error = exc
            continue
    raise last_error  # type: ignore[misc]


def file_list(day: str) -> list[str]:
    return [os.path.join("data", name) for name in CIC_DAYS[day]]


class Preprocessor:
    """Median imputer plus standard scaler fitted on the requested rows."""

    def __init__(self) -> None:
        self.pipeline = Pipeline(
            [
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler()),
            ]
        )

    def fit(self, X: pd.DataFrame | np.ndarray) -> "Preprocessor":
        self.pipeline.fit(X)
        return self

    def transform(self, X: pd.DataFrame | np.ndarray) -> np.ndarray:
        return np.asarray(self.pipeline.transform(X), dtype=np.float64)


class SupervisedAttackModel:
    def __init__(self, seed: int, class_weight: str | None = "balanced_subsample") -> None:
        self.seed = seed
        self.class_weight = class_weight
        self.pre = Preprocessor()
        self.classifier: RandomForestClassifier | None = None

    def fit(self, X: pd.DataFrame, y: np.ndarray) -> "SupervisedAttackModel":
        Z = self.pre.fit(X).transform(X)
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=self.seed,
            n_jobs=4,
            class_weight=self.class_weight,
        )
        self.classifier.fit(Z, y)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        assert self.classifier is not None
        return self.classifier.predict_proba(self.pre.transform(X))[:, 1].astype(np.float32)


class FamilyAugmentedAttackModel(SupervisedAttackModel):
    """Balanced RF trained on within-family interpolated attack rows."""

    def __init__(self, seed: int, families: list[str]) -> None:
        super().__init__(seed=seed, class_weight="balanced")
        self.families = families

    def fit(self, X: pd.DataFrame, y: np.ndarray, family_labels: np.ndarray) -> "FamilyAugmentedAttackModel":
        Z = self.pre.fit(X).transform(X)
        rng = np.random.default_rng(self.seed)
        synthetic_rows: list[np.ndarray] = []
        for family in self.families:
            class_rows = Z[family_labels == family]
            if len(class_rows) < 2:
                continue
            # Two synthetic rows per real row, capped, generated by convex
            # combinations of two rows from the same known family.
            count = min(max(2 * len(class_rows), 1000), 20_000)
            left = class_rows[rng.integers(0, len(class_rows), size=count)]
            right = class_rows[rng.integers(0, len(class_rows), size=count)]
            weight = rng.random((count, 1))
            synthetic = left + weight * (right - left)
            synthetic += rng.normal(0.0, 0.01, size=synthetic.shape)
            synthetic_rows.append(synthetic)
        if synthetic_rows:
            synthetic_matrix = np.vstack(synthetic_rows)
            Z_aug = np.vstack([Z, synthetic_matrix])
            y_aug = np.concatenate([y, np.ones(len(synthetic_matrix), dtype=y.dtype)])
        else:
            Z_aug, y_aug = Z, y
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            random_state=self.seed,
            n_jobs=4,
            class_weight=self.class_weight,
        )
        self.classifier.fit(Z_aug, y_aug)
        return self


class IsolationForestModel:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.pre = Preprocessor()
        self.classifier: IsolationForest | None = None

    def fit(self, X: pd.DataFrame) -> "IsolationForestModel":
        Z = self.pre.fit(X).transform(X)
        self.classifier = IsolationForest(
            n_estimators=100,
            random_state=self.seed,
            n_jobs=4,
            contamination="auto",
        )
        self.classifier.fit(Z)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        assert self.classifier is not None
        # score_samples is larger for normal points, so negate it.
        return (-self.classifier.score_samples(self.pre.transform(X))).astype(np.float32)


class PCAModel:
    def __init__(self, seed: int, n_components: int = 20) -> None:
        self.seed = seed
        self.n_components = n_components
        self.pre = Preprocessor()
        self.pca: PCA | None = None

    def fit(self, X: pd.DataFrame) -> "PCAModel":
        Z = self.pre.fit(X).transform(X)
        self.pca = PCA(n_components=self.n_components, random_state=self.seed)
        self.pca.fit(Z)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        assert self.pca is not None
        Z = self.pre.transform(X)
        reconstructed = self.pca.inverse_transform(self.pca.transform(Z))
        return np.mean((Z - reconstructed) ** 2, axis=1).astype(np.float32)


class MahalanobisModel:
    def __init__(self, seed: int) -> None:
        self.seed = seed
        self.pre = Preprocessor()
        self.mean: np.ndarray | None = None
        self.inverse_covariance: np.ndarray | None = None

    def fit(self, X: pd.DataFrame) -> "MahalanobisModel":
        Z = self.pre.fit(X).transform(X)
        self.mean = Z.mean(axis=0)
        covariance = np.cov(Z, rowvar=False)
        covariance = np.atleast_2d(covariance)
        covariance += np.eye(covariance.shape[0]) * 1e-3
        self.inverse_covariance = np.linalg.inv(covariance)
        return self

    def score(self, X: pd.DataFrame) -> np.ndarray:
        assert self.mean is not None and self.inverse_covariance is not None
        Z = self.pre.transform(X)
        difference = Z - self.mean
        distance_squared = np.einsum("ij,jk,ik->i", difference, self.inverse_covariance, difference)
        return np.sqrt(np.maximum(distance_squared, 0.0)).astype(np.float32)


def load_training_sample(
    files: list[str],
    feature_cols: list[str],
    benign_sample: int,
    seed: int,
    limit_rows: int | None = None,
) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    """Load all attacks and a deterministic benign sample."""
    attack_frames: list[pd.DataFrame] = []
    benign_frames: list[pd.DataFrame] = []
    total_benign = 0
    total_attack = 0
    # A fixed fraction is adequate; the exact target is not important as long
    # as the same rows are used for every arm.
    benign_fraction = benign_sample / 961_954.0
    rng = np.random.default_rng(seed)
    for path in files:
        for X, labels, _ in iter_feature_chunks(path, feature_cols, limit_rows=limit_rows):
            labels = labels.map(normalize_label)
            benign_mask = (labels == "BENIGN").to_numpy()
            total_benign += int(benign_mask.sum())
            total_attack += int((~benign_mask).sum())
            X = X.reset_index(drop=True)
            if benign_mask.any():
                benign = X.loc[benign_mask].copy()
                keep = rng.random(len(benign)) < benign_fraction
                if keep.any():
                    benign_frames.append(benign.loc[keep])
            if (~benign_mask).any():
                attack = X.loc[~benign_mask].copy()
                attack["_family"] = labels.loc[~benign_mask].to_numpy()
                attack_frames.append(attack)
    if not attack_frames:
        raise RuntimeError("No attack rows found in the training partition")
    attacks = pd.concat(attack_frames, ignore_index=True)
    benign = pd.concat(benign_frames, ignore_index=True) if benign_frames else pd.DataFrame(columns=feature_cols)
    training = pd.concat([benign[feature_cols], attacks[feature_cols]], ignore_index=True)
    labels = np.concatenate(
        [
            np.zeros(len(benign), dtype=np.int8),
            np.ones(len(attacks), dtype=np.int8),
        ]
    )
    families = np.concatenate(
        [
            np.full(len(benign), "BENIGN", dtype=object),
            attacks["_family"].to_numpy(),
        ]
    )
    order = np.random.default_rng(seed).permutation(len(training))
    training = training.iloc[order].reset_index(drop=True)
    labels = labels[order]
    families = families[order]
    print(
        f"Training sample: {len(training):,} rows ({int(labels.sum()):,} attacks, "
        f"{int((labels == 0).sum()):,} benign) from {total_attack:,} attacks and "
        f"{total_benign:,} benign source rows"
    )
    return training, labels, families


def day_for_path(path: str) -> str:
    name = os.path.basename(path)
    for day in ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"):
        if name.startswith(day):
            return day
    raise ValueError(f"Cannot infer day from {path}")


def score_files_simple(
    files: list[str],
    model: Any,
    feature_cols: list[str],
    limit_rows: int | None = None,
) -> dict[str, Any]:
    """Stream scores while keeping labels and families compact."""
    score_parts: list[np.ndarray] = []
    truth_parts: list[np.ndarray] = []
    family_parts: list[np.ndarray] = []
    day_parts: list[np.ndarray] = []
    families: list[str] = []
    family_to_code: dict[str, int] = {}
    for path in files:
        day = day_for_path(path)
        for X, labels, source in iter_feature_chunks(path, feature_cols, limit_rows=limit_rows):
            clean = labels.map(normalize_label)
            scores = np.asarray(model.score(X), dtype=np.float32)
            codes = np.empty(len(clean), dtype=np.int16)
            for index, family in enumerate(clean):
                code = family_to_code.get(family)
                if code is None:
                    code = len(families)
                    family_to_code[family] = code
                    families.append(family)
                codes[index] = code
            score_parts.append(scores)
            truth_parts.append((clean != "BENIGN").to_numpy(dtype=np.int8))
            family_parts.append(codes)
            day_parts.append(np.full(len(clean), day, dtype=object))
            print(f"  scored {source}: {len(clean):,} rows")
    return {
        "score": np.concatenate(score_parts),
        "binary_truth": np.concatenate(truth_parts),
        "family_codes": np.concatenate(family_parts),
        "families": families,
        "days": np.concatenate(day_parts),
    }


def load_cached_reference(seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
    validation = np.load(f"models/eval_cache/rf_seed{seed}_validation.npz", allow_pickle=True)
    test = np.load(f"models/eval_cache/rf_seed{seed}_test.npz", allow_pickle=True)

    def unpack(data: Any) -> dict[str, Any]:
        families = [str(item) for item in data["families"]]
        days = [str(item) for item in data["days"]]
        return {
            "score": data["attack_score"].astype(np.float32),
            "binary_truth": data["binary_truth"].astype(np.int8),
            "family_codes": data["family_codes"].astype(np.int16),
            "families": families,
            "days": np.array([days[int(code)] for code in data["day_codes"]], dtype=object),
        }

    return unpack(validation), unpack(test)


def wilson_interval(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * np.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [float(max(0.0, center - margin)), float(min(1.0, center + margin))]


def binary_ece(truth: np.ndarray, probability: np.ndarray, bins: int = 10) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    error = 0.0
    for index in range(bins):
        if index == bins - 1:
            mask = (probability >= edges[index]) & (probability <= edges[index + 1])
        else:
            mask = (probability >= edges[index]) & (probability < edges[index + 1])
        if np.any(mask):
            error += float(mask.mean()) * abs(float(truth[mask].mean()) - float(probability[mask].mean()))
    return float(error)


def fit_platt(score: np.ndarray, truth: np.ndarray) -> LogisticRegression:
    model = LogisticRegression(C=1e6, max_iter=2000, solver="lbfgs")
    model.fit(np.asarray(score, dtype=np.float64).reshape(-1, 1), truth)
    return model


def calibrated_probability(model: LogisticRegression, score: np.ndarray) -> np.ndarray:
    probability = model.predict_proba(np.asarray(score, dtype=np.float64).reshape(-1, 1))[:, 1]
    return np.clip(probability, 1e-6, 1 - 1e-6)


def evaluate_arm_at_threshold(
    result: dict[str, Any],
    threshold: float,
    probability: np.ndarray,
    train_families: set[str],
) -> dict[str, Any]:
    truth = result["binary_truth"]
    score = result["score"]
    families = [result["families"][code] for code in result["family_codes"]]
    selected = score >= threshold
    benign = truth == 0
    attack = truth == 1
    tp = int(np.sum(selected & attack))
    fp = int(np.sum(selected & benign))
    fn = int(np.sum(~selected & attack))
    tn = int(np.sum(~selected & benign))
    metrics: dict[str, Any] = {
        "threshold": float(threshold),
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "recall": tp / (tp + fn) if tp + fn else 0.0,
        "precision": tp / (tp + fp) if tp + fp else 0.0,
        "alert_rate": float(np.mean(selected)),
        "alerts": int(selected.sum()),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "fp_per_10k_benign": float(fp / (fp + tn) * 10_000) if fp + tn else 0.0,
        "recall_wilson_95": wilson_interval(tp, tp + fn),
        "pr_auc": float(average_precision_score(truth, score)),
        "roc_auc": float(roc_auc_score(truth, score)),
        "calibration": {
            "brier": float(brier_score_loss(truth, probability)),
            "ece_10_bins": binary_ece(truth, probability),
        },
    }
    per_family: dict[str, Any] = {}
    for family in FAMILY_ORDER:
        if family == "BENIGN":
            continue
        mask = np.array([name == family for name in families], dtype=bool)
        support = int(mask.sum())
        if support == 0:
            continue
        detected = int(np.sum(selected & mask))
        per_family[family] = {
            "support": support,
            "detected": detected,
            "recall": detected / support,
            "recall_wilson_95": wilson_interval(detected, support),
            "average_precision": float(average_precision_score(mask.astype(int), score)),
            "seen_in_training": family in train_families,
        }
    metrics["per_family"] = per_family
    return metrics


def per_day_metrics(
    result: dict[str, Any],
    threshold: float,
    probability: np.ndarray,
    train_families: set[str],
) -> dict[str, Any]:
    days = result["days"]
    output: dict[str, Any] = {}
    for day in ("Thursday", "Friday"):
        mask = days == day
        if not np.any(mask):
            continue
        subset = {
            "score": result["score"][mask],
            "binary_truth": result["binary_truth"][mask],
            "family_codes": result["family_codes"][mask],
            "families": result["families"],
            "days": days[mask],
        }
        output[day] = evaluate_arm_at_threshold(subset, threshold, probability[mask], train_families)
    return output


def evaluate_cached_reference(seed: int, train_families: set[str]) -> dict[str, Any]:
    validation, test = load_cached_reference(seed)
    threshold_info = select_threshold_at_max_fpr(
        validation["binary_truth"], validation["score"], TARGET_FPR
    )
    if threshold_info is None:
        raise RuntimeError(f"Cached reference seed {seed}: threshold selection failed")
    platt = fit_platt(validation["score"], validation["binary_truth"])
    probability = calibrated_probability(platt, test["score"])
    metrics = evaluate_arm_at_threshold(test, threshold_info["threshold"], probability, train_families)
    metrics["validation"] = {
        "threshold": threshold_info["threshold"],
        "fpr": threshold_info["validation_fpr"],
        "recall": threshold_info["validation_tpr"],
        "pr_auc": float(average_precision_score(validation["binary_truth"], validation["score"])),
        "calibration": {
            "brier": float(brier_score_loss(validation["binary_truth"], calibrated_probability(platt, validation["score"]))),
            "ece_10_bins": binary_ece(validation["binary_truth"], calibrated_probability(platt, validation["score"])),
        },
    }
    metrics["per_day"] = per_day_metrics(test, threshold_info["threshold"], probability, train_families)
    budgets = evaluate_alert_budgets(
        test["binary_truth"],
        test["score"],
        y_true_families=np.array([test["families"][code] for code in test["family_codes"]], dtype=object),
        budgets_per_10k=[50, 100],
        fixed_counts=[],
    )
    metrics["alert_budgets"] = budgets
    return metrics


def evaluate_new_arm(
    validation: dict[str, Any],
    test: dict[str, Any],
    train_families: set[str],
    probability_test: np.ndarray | None = None,
) -> dict[str, Any]:
    threshold_info = select_threshold_at_max_fpr(
        validation["binary_truth"], validation["score"], TARGET_FPR
    )
    if threshold_info is None:
        raise RuntimeError("threshold selection failed")
    platt = fit_platt(validation["score"], validation["binary_truth"])
    probability_test = (
        calibrated_probability(platt, test["score"]) if probability_test is None else probability_test
    )
    metrics = evaluate_arm_at_threshold(test, threshold_info["threshold"], probability_test, train_families)
    metrics["validation"] = {
        "threshold": threshold_info["threshold"],
        "fpr": threshold_info["validation_fpr"],
        "recall": threshold_info["validation_tpr"],
        "pr_auc": float(average_precision_score(validation["binary_truth"], validation["score"])),
        "calibration": {
            "brier": float(brier_score_loss(validation["binary_truth"], calibrated_probability(platt, validation["score"]))),
            "ece_10_bins": binary_ece(validation["binary_truth"], calibrated_probability(platt, validation["score"])),
        },
    }
    metrics["per_day"] = per_day_metrics(test, threshold_info["threshold"], probability_test, train_families)
    budgets = evaluate_alert_budgets(
        test["binary_truth"],
        test["score"],
        y_true_families=np.array([test["families"][code] for code in test["family_codes"]], dtype=object),
        budgets_per_10k=[50, 100],
        fixed_counts=[],
    )
    metrics["alert_budgets"] = budgets
    return metrics


def aggregate(seed_results: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ["fpr", "recall", "precision", "alert_rate", "pr_auc", "roc_auc", "fp_per_10k_benign"]
    output: dict[str, Any] = {}
    for key in keys:
        values = [result[key] for result in seed_results]
        output[key] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
            "values": values,
        }
    for key in ("brier", "ece_10_bins"):
        values = [result["calibration"][key] for result in seed_results]
        output[key] = {
            "mean": float(np.mean(values)),
            "std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
            "values": values,
        }
    family_names = sorted({name for result in seed_results for name in result["per_family"]})
    output["per_family"] = {}
    for family in family_names:
        values = [
            result["per_family"][family]["recall"]
            for result in seed_results
            if family in result["per_family"]
        ]
        supports = {
            result["per_family"][family]["support"]
            for result in seed_results
            if family in result["per_family"]
        }
        output["per_family"][family] = {
            "support": sorted(supports)[0] if supports else 0,
            "recall_mean": float(np.mean(values)),
            "recall_std": float(np.std(values, ddof=1)) if len(values) > 1 else 0.0,
            "recall_values": values,
        }
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the D6 unseen-family/Botnet experiment.")
    parser.add_argument("--output", default="docs/d6_unseen_family_results.json")
    parser.add_argument("--limit-eval-rows", type=int, default=None, help="Debug only: limit evaluation rows per file")
    parser.add_argument("--seeds", default="42,43,44,45,46")
    args = parser.parse_args()

    global FEATURE_COLS
    FEATURE_COLS = list(__import__("joblib").load("models/feature_names.pkl"))
    seeds = [int(item) for item in args.seeds.split(",")]
    started = time.time()

    train_files = file_list("Monday") + file_list("Tuesday")
    validation_files = file_list("Wednesday")
    test_files = file_list("Thursday") + file_list("Friday")

    train_X, train_y, train_families_all = load_training_sample(
        train_files, FEATURE_COLS, TRAIN_BENIGN_SAMPLE, TRAIN_SAMPLE_SEED, None
    )
    attack_families = sorted(set(train_families_all) - {"BENIGN"})
    train_families = set(attack_families)
    print(f"Training attack families: {attack_families}")

    results: dict[str, Any] = {
        "protocol": "docs/D6_EXPERIMENT_PROTOCOL.md",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_schema": "cic-ids-2017-80f-45cd75ce849b",
        "seeds": seeds,
        "training_sample": {
            "rows": int(len(train_X)),
            "attacks": int(train_y.sum()),
            "benign": int((train_y == 0).sum()),
            "benign_source_sample_seed": TRAIN_SAMPLE_SEED,
            "attack_families": attack_families,
            "declared_deviation": "all training attacks plus 200k benign rows; see protocol",
        },
        "validation_partition": "Wednesday",
        "test_partition": "Thursday + Friday",
        "arms": {},
    }

    # Reference arm: cached full-data RF predictions.  This is not retrained.
    reference_seeds = []
    for seed in seeds:
        print(f"\n=== Reference (cached full-data RF) seed {seed} ===")
        reference_seeds.append(evaluate_cached_reference(seed, train_families))
        print(
            f"  Bot recall={reference_seeds[-1]['per_family'].get('Bot', {}).get('recall', float('nan')):.4f} "
            f"FPR={reference_seeds[-1]['fpr']:.4f}"
        )
    results["arms"]["R_full_data_rf_reference"] = {
        "description": "Frozen full-data Random Forest predictions from models/eval_cache; no retraining.",
        "seeds": {str(seed): value for seed, value in zip(seeds, reference_seeds)},
        "aggregate": aggregate(reference_seeds),
    }

    # Arm A: class weighting on the fixed training sample.
    arm_a_seeds = []
    arm_a_cache: dict[int, tuple[dict[str, Any], dict[str, Any]]] = {}
    for seed in seeds:
        print(f"\n=== Arm A (class weighting) seed {seed} ===")
        model = SupervisedAttackModel(seed=seed, class_weight="balanced_subsample")
        model.fit(train_X, train_y)
        validation = score_files_simple(validation_files, model, FEATURE_COLS, args.limit_eval_rows)
        test = score_files_simple(test_files, model, FEATURE_COLS, args.limit_eval_rows)
        arm_a_cache[seed] = (validation, test)
        arm_a_seeds.append(evaluate_new_arm(validation, test, train_families))
        print(
            f"  Bot recall={arm_a_seeds[-1]['per_family'].get('Bot', {}).get('recall', float('nan')):.4f} "
            f"FPR={arm_a_seeds[-1]['fpr']:.4f}"
        )
    results["arms"]["A_class_weighting"] = {
        "description": "Binary Random Forest with balanced_subsample class weights on the fixed sample.",
        "seeds": {str(seed): value for seed, value in zip(seeds, arm_a_seeds)},
        "aggregate": aggregate(arm_a_seeds),
    }

    # Arm B: family-aware interpolation augmentation.
    arm_b_seeds = []
    for seed in seeds:
        print(f"\n=== Arm B (family-aware augmentation) seed {seed} ===")
        model = FamilyAugmentedAttackModel(seed=seed, families=attack_families)
        model.fit(train_X, train_y, train_families_all)
        validation = score_files_simple(validation_files, model, FEATURE_COLS, args.limit_eval_rows)
        test = score_files_simple(test_files, model, FEATURE_COLS, args.limit_eval_rows)
        arm_b_seeds.append(evaluate_new_arm(validation, test, train_families))
        print(
            f"  Bot recall={arm_b_seeds[-1]['per_family'].get('Bot', {}).get('recall', float('nan')):.4f} "
            f"FPR={arm_b_seeds[-1]['fpr']:.4f}"
        )
    results["arms"]["B_family_aware_augmentation"] = {
        "description": "Balanced RF with within-known-family interpolation augmentation.",
        "seeds": {str(seed): value for seed, value in zip(seeds, arm_b_seeds)},
        "aggregate": aggregate(arm_b_seeds),
    }

    # Anomaly arms C1/C2/C3.
    anomaly_factories = {
        "C1_isolation_forest": lambda seed: IsolationForestModel(seed),
        "C2_pca_reconstruction": lambda seed: PCAModel(seed),
        "C3_mahalanobis": lambda seed: MahalanobisModel(seed),
    }
    anomaly_results: dict[str, list[dict[str, Any]]] = {name: [] for name in anomaly_factories}
    anomaly_validation_cache: dict[int, dict[str, Any]] = {}
    anomaly_test_cache: dict[int, dict[str, Any]] = {}
    benign_X = train_X.loc[train_y == 0].reset_index(drop=True)
    for seed in seeds:
        for name, factory in anomaly_factories.items():
            print(f"\n=== {name} seed {seed} ===")
            model = factory(seed)
            if isinstance(model, IsolationForestModel):
                model.fit(benign_X)
            elif isinstance(model, PCAModel):
                model.fit(benign_X)
            else:
                model.fit(benign_X)
            validation = score_files_simple(validation_files, model, FEATURE_COLS, args.limit_eval_rows)
            test = score_files_simple(test_files, model, FEATURE_COLS, args.limit_eval_rows)
            if name == "C1_isolation_forest":
                anomaly_validation_cache[seed] = validation
                anomaly_test_cache[seed] = test
            anomaly_results[name].append(evaluate_new_arm(validation, test, train_families))
            print(
                f"  Bot recall={anomaly_results[name][-1]['per_family'].get('Bot', {}).get('recall', float('nan')):.4f} "
                f"FPR={anomaly_results[name][-1]['fpr']:.4f}"
            )
    for name, seed_results in anomaly_results.items():
        results["arms"][name] = {
            "description": {
                "C1_isolation_forest": "Benign-only Isolation Forest; primary open-set arm.",
                "C2_pca_reconstruction": "Benign-only PCA reconstruction error; sensitivity arm.",
                "C3_mahalanobis": "Benign-only regularised Mahalanobis distance; sensitivity arm.",
            }[name],
            "seeds": {str(seed): value for seed, value in zip(seeds, seed_results)},
            "aggregate": aggregate(seed_results),
        }

    # Arm D: hybrid of A and C1, with alpha chosen on validation AP.
    hybrid_seeds = []
    hybrid_validation: list[dict[str, Any]] = []
    for index, seed in enumerate(seeds):
        print(f"\n=== Arm D (hybrid) seed {seed} ===")
        validation_a, test_a = arm_a_cache[seed]
        validation_c = anomaly_validation_cache[seed]
        test_c = anomaly_test_cache[seed]
        # Normalise each score with validation-benign mean/std, then sigmoid.
        def normalise(reference_benign: np.ndarray, value: np.ndarray) -> np.ndarray:
            mean = float(np.mean(reference_benign))
            std = float(np.std(reference_benign)) or 1.0
            return 1.0 / (1.0 + np.exp(-((value - mean) / std)))

        val_benign_mask = validation_a["binary_truth"] == 0
        sup_val_norm = normalise(validation_a["score"][val_benign_mask], validation_a["score"])
        anom_val_norm = normalise(validation_c["score"][val_benign_mask], validation_c["score"])
        test_benign_mask = test_a["binary_truth"] == 0
        sup_test_norm = normalise(validation_a["score"][val_benign_mask], test_a["score"])
        anom_test_norm = normalise(validation_c["score"][val_benign_mask], test_c["score"])
        best_alpha = None
        best_ap = -1.0
        for alpha in (0.0, 0.25, 0.5, 0.75, 1.0):
            combined = alpha * sup_val_norm + (1.0 - alpha) * anom_val_norm
            ap = float(average_precision_score(validation_a["binary_truth"], combined))
            if ap > best_ap:
                best_ap = ap
                best_alpha = alpha
        assert best_alpha is not None
        combined_validation = {
            "score": (best_alpha * sup_val_norm + (1.0 - best_alpha) * anom_val_norm).astype(np.float32),
            "binary_truth": validation_a["binary_truth"],
            "family_codes": validation_a["family_codes"],
            "families": validation_a["families"],
            "days": validation_a["days"],
        }
        combined_test = {
            "score": (best_alpha * sup_test_norm + (1.0 - best_alpha) * anom_test_norm).astype(np.float32),
            "binary_truth": test_a["binary_truth"],
            "family_codes": test_a["family_codes"],
            "families": test_a["families"],
            "days": test_a["days"],
        }
        metrics = evaluate_new_arm(combined_validation, combined_test, train_families)
        metrics["selected_alpha"] = best_alpha
        metrics["validation_selection_ap"] = best_ap
        hybrid_seeds.append(metrics)
        hybrid_validation.append({"seed": seed, "alpha": best_alpha, "ap": best_ap})
        print(
            f"  alpha={best_alpha} Bot recall={metrics['per_family'].get('Bot', {}).get('recall', float('nan')):.4f} "
            f"FPR={metrics['fpr']:.4f}"
        )
    results["arms"]["D_hybrid_supervised_anomaly"] = {
        "description": "Validation-selected blend of arm A and C1 scores.",
        "seeds": {str(seed): value for seed, value in zip(seeds, hybrid_seeds)},
        "aggregate": aggregate(hybrid_seeds),
        "selection": hybrid_validation,
    }

    results["elapsed_seconds"] = round(time.time() - started, 1)
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2, allow_nan=False)
    print(f"\nWrote {args.output} in {results['elapsed_seconds']} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
