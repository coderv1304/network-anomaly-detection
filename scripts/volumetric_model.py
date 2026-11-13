#!/usr/bin/env python
"""P2B protocol audit for the re-scoped volumetric/scanning model.

The P2B contract asks for supervised binary heads trained on Monday-Tuesday,
validated on Wednesday, and tested on Thursday-Friday. This script checks that
the frozen partitions can support that protocol before any model is trained.

It does not train a model, does not write a registry row, and does not touch the
serving artifact. When the audit finds the protocol infeasible it records the
blocker, the evidence, and the amendments that would require human approval.

Examples:
    python scripts/volumetric_model.py \
        --output docs/VOLUMETRIC_MODEL.json \
        --report docs/VOLUMETRIC_DETECTOR.md
"""

from __future__ import annotations

import argparse
import collections
import gc
import json
import os
import sys
from typing import Any, Iterable

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import CIC_DAYS  # noqa: E402
from scripts.rule_baselines import (  # noqa: E402
    EXCLUDED_LABELS,
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    _read_raw_label_counts,
    _sha256_file,
    binary_truth,
    load_partition,
    primary_mask,
)

ARTIFACT_VERSION = "volumetric-model-v1"
P2A_ARTIFACT = os.path.join(PROJECT_ROOT, "docs", "rule_baselines.json")
SERVING_ARTIFACT = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

TRAIN_DAYS = {"Monday": CIC_DAYS["Monday"], "Tuesday": CIC_DAYS["Tuesday"]}
VALIDATION_DAYS = {"Wednesday": CIC_DAYS["Wednesday"]}
TEST_DAYS = {"Thursday": CIC_DAYS["Thursday"], "Friday": CIC_DAYS["Friday"]}

PROTOCOL = {
    "train_days": list(TRAIN_DAYS),
    "validation_days": list(VALIDATION_DAYS),
    "test_days": list(TEST_DAYS),
    "cv": (
        "expanding-window time-series CV inside training days only; "
        "3 folds, fit on earlier windows and validate on the next"
    ),
    "grid": {
        "logistic_regression": {"C": [0.1, 1.0, 10.0]},
        "random_forest": {
            "n_estimators": [100, 300],
            "max_depth": [None, 20],
        },
        "isolation_forest": {
            "n_estimators": [100],
            "contamination": ["auto", 0.01],
        },
        "gradient_boosting": "optional; same protocol",
    },
    "seeds": [42, 43, 44, 45, 46],
    "budgets_per_10k": [10, 100],
    "multiple_comparisons": "Holm-Bonferroni across families and budgets",
    "paired_test": "McNemar on identical flows with discordant counts",
    "threshold_partition": "Wednesday only",
}


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------
def partition_summary(labels: np.ndarray) -> dict[str, Any]:
    """Count primary positives, negatives, and excluded rows."""
    array = np.asarray(labels, dtype=object)
    keep = primary_mask(array)
    truth = binary_truth(array[keep])
    counts = collections.Counter(array)
    excluded = collections.Counter(
        label for label in array if label in EXCLUDED_LABELS
    )
    positives = int(truth.sum())
    negatives = int(truth.size - positives)
    return {
        "rows": int(array.size),
        "primary_rows": int(keep.sum()),
        "positives": positives,
        "negatives": negatives,
        "excluded_rows": int((~keep).sum()),
        "benchmark_prevalence": (positives / (positives + negatives))
        if positives + negatives
        else None,
        "label_counts": {str(key): int(value) for key, value in sorted(counts.items())},
        "excluded_label_counts": {
            str(key): int(value) for key, value in sorted(excluded.items())
        },
    }


def assess_feasibility(train_positives: int) -> dict[str, Any]:
    """Decide which P2B model families the training partition can support.

    Logistic regression and random forest need labelled positives. Isolation
    Forest is unsupervised, but it cannot satisfy the pack's supervised
    comparison on its own.
    """
    supervised = int(train_positives) > 0
    return {
        "supervised_binary_heads": supervised,
        "logistic_regression": supervised,
        "random_forest": supervised,
        "isolation_forest": True,
        "full_p2b_comparison": supervised,
        "reason": (
            "The training partition contains target positives."
            if supervised
            else (
                "The training partition contains zero volumetric/scanning "
                "positives. A supervised binary head has no positive class to "
                "fit. Only the unsupervised Isolation Forest is trainable, and "
                "it cannot satisfy the full rules-vs-supervised comparison."
            )
        ),
    }


def amendment_options() -> list[dict[str, str]]:
    """List protocol amendments. None are executed by this audit."""
    return [
        {
            "id": "A1",
            "name": "Time-ordered holdout inside Wednesday",
            "change": (
                "Train on the earlier portion of Wednesday, select thresholds on "
                "the later portion, keep Thursday-Friday as the test partition."
            ),
            "pros": "Creates training positives while preserving a held-out test day range.",
            "cons": (
                "Wednesday is currently the validation partition; the amendment "
                "reduces validation size and changes the preregistered split."
            ),
            "requires": "Human approval; timestamp ordering must be verified.",
            "recommended": "yes, if the supervised comparison is required",
        },
        {
            "id": "A2",
            "name": "Unsupervised-only P2B",
            "change": (
                "Train Isolation Forest on Monday-Tuesday benign traffic and "
                "freeze thresholds on Wednesday. Do not report LogReg/RF."
            ),
            "pros": "Uses the existing split unchanged and needs no new labels.",
            "cons": (
                "Cannot answer the pack's rules-vs-supervised question and "
                "leaves the main model comparison unexecuted."
            ),
            "requires": "Human approval of a partial P2B scope.",
            "recommended": "no, unless the supervised comparison is out of scope",
        },
        {
            "id": "A3",
            "name": "Move volumetric days into training",
            "change": "Train on Monday-Wednesday and test on Thursday-Friday.",
            "pros": "Adds the DoS families to training.",
            "cons": (
                "Removes the independent validation partition and makes "
                "threshold selection and test reporting depend on the same days."
            ),
            "requires": "Human approval; not recommended.",
            "recommended": "no",
        },
        {
            "id": "A4",
            "name": "External volumetric capture",
            "change": (
                "Acquire a labelled capture with volumetric/scanning traffic and "
                "use it as an additional training or validation source."
            ),
            "pros": "Adds independent positives and supports cross-dataset claims.",
            "cons": "Requires data, licensing, and capture effort that do not exist yet.",
            "requires": "External data and human approval.",
            "recommended": "yes, as the longer-term fix",
        },
    ]


def build_blocker(train_summary: dict[str, Any]) -> dict[str, Any] | None:
    """Return the blocker record when the training partition has no positives."""
    if int(train_summary["positives"]) > 0:
        return None
    return {
        "code": "training_partition_has_no_target_positives",
        "detail": (
            "The frozen Monday-Tuesday training partition contains "
            f"{train_summary['positives']:,} volumetric/scanning positives "
            f"across {train_summary['primary_rows']:,} primary rows. The "
            "only non-benign training labels are FTP-Patator and SSH-Patator, "
            "which the P2A label policy excludes. A supervised binary head "
            "cannot be fitted, so no LogReg or Random Forest comparison is "
            "possible under the preregistered split."
        ),
        "evidence": {
            "train_primary_rows": train_summary["primary_rows"],
            "train_positives": train_summary["positives"],
            "train_negatives": train_summary["negatives"],
            "train_excluded_rows": train_summary["excluded_rows"],
            "train_excluded_labels": train_summary["excluded_label_counts"],
        },
    }


def raw_file_audit(day_files: dict[str, list[str]]) -> dict[str, Any]:
    """Read only label counts and hashes, exactly as P2A does."""
    per_file: dict[str, Any] = {}
    aggregate: collections.Counter = collections.Counter()
    for filename in [name for files in day_files.values() for name in files]:
        path = os.path.join(DATA_DIR, filename)
        counts = _read_raw_label_counts(path)
        per_file[filename] = {"counts": counts, "sha256": _sha256_file(path)}
        aggregate.update(counts)
    return {"per_file": per_file, "aggregate": dict(aggregate)}


def _load_p2a() -> dict[str, Any]:
    if not os.path.exists(P2A_ARTIFACT):
        raise FileNotFoundError(
            f"{P2A_ARTIFACT} is missing; run scripts/rule_baselines.py first"
        )
    with open(P2A_ARTIFACT, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _partition_evidence(p2a: dict[str, Any], name: str) -> dict[str, Any]:
    block = p2a["partitions"][name]
    return {
        "days": block["days"],
        "source_files": block["source_files"],
        "rows_after_dedup": block["rows_after_dedup"],
        "primary_rows": block["primary_rows"],
        "positives": block["positives"],
        "negatives": block["negatives"],
        "excluded_rows": block["excluded_rows"],
        "benchmark_prevalence": block["benchmark_prevalence"],
        "label_counts": block["label_counts"],
        "excluded_label_counts": block["excluded_label_counts"],
        "repairs": block["repairs"],
    }


def build_payload() -> dict[str, Any]:
    p2a = _load_p2a()
    print("auditing raw training labels", flush=True)
    train_raw = raw_file_audit(TRAIN_DAYS)

    print("loading frozen training partition", flush=True)
    train = load_partition("train", TRAIN_DAYS)
    train_summary = partition_summary(train["labels"])
    train_summary["days"] = list(TRAIN_DAYS)
    train_summary["source_files"] = [
        filename for files in TRAIN_DAYS.values() for filename in files
    ]
    train_summary["rows_after_dedup"] = int(train["rows"])
    train_summary["repairs"] = train["repairs"]
    raw_total = sum(train_raw["aggregate"].values())
    train_summary["raw_rows"] = raw_total
    train_summary["dedup_removed_rows"] = raw_total - int(train["rows"])
    del train
    gc.collect()

    validation = _partition_evidence(p2a, "validation")
    test = _partition_evidence(p2a, "test")

    feasibility = assess_feasibility(train_summary["positives"])
    blocked = not feasibility["full_p2b_comparison"]
    blocker = build_blocker(train_summary)

    return {
        "artifact_version": ARTIFACT_VERSION,
        "method": "p2b_protocol_audit",
        "status": "blocked" if blocked else "ready",
        "scope": (
            "Flow-based detector for volumetric and scanning behavior. "
            "Not a general NIDS. Botnet, web attacks, infiltration, zero-day, "
            "and blocking are out of scope."
        ),
        "protocol": PROTOCOL,
        "label_policy": {
            "positive_labels": sorted(POSITIVE_LABELS),
            "negative_labels": sorted(NEGATIVE_LABELS),
            "excluded_labels": dict(sorted(EXCLUDED_LABELS.items())),
        },
        "partitions": {
            "train": train_summary,
            "validation": validation,
            "test": test,
        },
        "training_label_audit": train_raw,
        "feasibility": feasibility,
        "blocker": blocker,
        "amendments": amendment_options(),
        "execution": {
            "models_trained": [],
            "registry_rows_added": [],
            "metrics_computed": False,
            "reason": (
                "No supervised model can be trained under the preregistered "
                "split. The audit does not substitute a different split or "
                "synthetic positives."
            )
            if blocked
            else "Training may proceed.",
        },
        "artifact_identity": {
            "serving_artifact": os.path.relpath(SERVING_ARTIFACT, PROJECT_ROOT).replace(
                "\\", "/"
            ),
            "serving_sha256": _sha256_file(SERVING_ARTIFACT)
            if os.path.exists(SERVING_ARTIFACT)
            else None,
            "p2a_artifact": os.path.relpath(P2A_ARTIFACT, PROJECT_ROOT).replace(
                "\\", "/"
            ),
            "p2a_sha256": _sha256_file(P2A_ARTIFACT),
        },
        "notes": [
            "No model is trained, no registry row is written, and the serving artifact is untouched.",
            "The blocker is a property of the frozen split, not a bug in the model code.",
            "Amendments are listed but not executed; P2B has a human approval gate for a new artifact.",
            "The test partition is not used for threshold selection or model selection.",
            "Rules remain the only evaluated Tier A baseline; see docs/RULE_BASELINES.md.",
        ],
    }


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------
def render_markdown(payload: dict[str, Any]) -> str:
    train = payload["partitions"]["train"]
    validation = payload["partitions"]["validation"]
    test = payload["partitions"]["test"]
    blocker = payload["blocker"]
    feasibility = payload["feasibility"]
    lines: list[str] = []
    lines.append("# Volumetric Detector (Phase P2B)")
    lines.append("")
    status = payload["status"].upper()
    lines.append(f"**Status:** {status}. **Scope:** flow-based volumetric and scanning behavior; not a general NIDS.")
    lines.append("")
    lines.append("**Artifact:** [`VOLUMETRIC_MODEL.json`](VOLUMETRIC_MODEL.json). "
                 "**Audit script:** [`../scripts/volumetric_model.py`](../scripts/volumetric_model.py). "
                 "**Baselines:** [`RULE_BASELINES.md`](RULE_BASELINES.md).")
    lines.append("")
    lines.append("This document answers the P2B question: can the preregistered split support the "
                 "rules-versus-supervised comparison? It does not report model metrics, because the "
                 "audit found that the training partition cannot fit a supervised positive class.")
    lines.append("")
    lines.append("## Protocol as written")
    lines.append("")
    lines.append("| Item | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Train days | {', '.join(payload['protocol']['train_days'])} |")
    lines.append(f"| Validation days | {', '.join(payload['protocol']['validation_days'])} |")
    lines.append(f"| Test days | {', '.join(payload['protocol']['test_days'])} |")
    lines.append(f"| Seeds | {', '.join(str(seed) for seed in payload['protocol']['seeds'])} |")
    lines.append(f"| Budgets | {', '.join(str(b) for b in payload['protocol']['budgets_per_10k'])} alerts / 10k |")
    lines.append("| Threshold partition | Wednesday only |")
    lines.append("")
    lines.append("## Partition audit")
    lines.append("")
    lines.append("| Partition | Days | Rows after dedup | Primary rows | Positives | Negatives | Excluded | Benchmark prevalence |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    for name, block in (("Train", train), ("Validation", validation), ("Test", test)):
        prevalence = block["benchmark_prevalence"]
        prevalence_text = "n/a" if prevalence is None else f"{prevalence * 100:.2f}%"
        lines.append(
            f"| {name} | {', '.join(block['days'])} | {block['rows_after_dedup']:,} | "
            f"{block['primary_rows']:,} | {block['positives']:,} | {block['negatives']:,} | "
            f"{block['excluded_rows']:,} | {prevalence_text} |"
        )
    lines.append("")
    lines.append("Training label counts after dedup: "
                 + ", ".join(f"`{label}` {count:,}" for label, count in train["label_counts"].items())
                 + ".")
    lines.append("")
    lines.append(f"The raw training files contain {train['raw_rows']:,} rows; the frozen loader removes "
                 f"{train['dedup_removed_rows']:,} cross-file duplicates, leaving "
                 f"{train['rows_after_dedup']:,}.")
    lines.append("")
    lines.append("The only non-benign training labels are the two credential-attack families, "
                 "which the P2A policy excludes. There is no volumetric or scanning positive in "
                 "the training partition.")
    lines.append("")
    lines.append("## Blocker")
    lines.append("")
    if blocker is None:
        lines.append("No blocker. The training partition contains target positives.")
    else:
        lines.append(f"**`{blocker['code']}`**: {blocker['detail']}")
        lines.append("")
        lines.append("This is a split-design problem, not a code defect. Training on test labels, "
                     "relabelling patators as volumetric, or synthesising positives would each break "
                     "the label policy or the integrity contract. None were done.")
    lines.append("")
    lines.append("## Feasibility")
    lines.append("")
    lines.append("| Model family | Trainable under the preregistered split |")
    lines.append("| --- | --- |")
    for key, label in (
        ("logistic_regression", "Logistic Regression"),
        ("random_forest", "Random Forest"),
        ("isolation_forest", "Isolation Forest"),
        ("full_p2b_comparison", "Full P2B comparison"),
    ):
        lines.append(f"| {label} | {'yes' if feasibility[key] else 'no'} |")
    lines.append("")
    lines.append(feasibility["reason"])
    lines.append("")
    lines.append("## Amendments requiring human approval")
    lines.append("")
    lines.append("| ID | Amendment | Change | Pros | Cons | Recommended |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for option in payload["amendments"]:
        lines.append(
            f"| {option['id']} | {option['name']} | {option['change']} | "
            f"{option['pros']} | {option['cons']} | {option['recommended']} |"
        )
    lines.append("")
    lines.append("The audit does not execute an amendment. P2B's human gate requires approval of a "
                 "new artifact, and changing the split changes every downstream claim.")
    lines.append("")
    lines.append("Isolation Forest is technically trainable on the existing split, but it cannot answer the "
                 "pack's rules-versus-supervised question on its own. It was not run as a partial substitute, "
                 "because a one-model result would be easy to misread as the P2B comparison.")
    lines.append("")
    lines.append("## What was not executed")
    lines.append("")
    lines.append("- No Logistic Regression, Random Forest, Gradient Boosting, or Isolation Forest model was trained.")
    lines.append("- No model artifact or registry row was created.")
    lines.append("- No recall, FPR, PPV, calibration, or McNemar result is reported.")
    lines.append("- The serving artifact and its threshold are unchanged.")
    lines.append("")
    lines.append("## Decision")
    lines.append("")
    lines.append("**Rules remain the only evaluated Tier A baseline.** The P2B supervised comparison "
                 "is blocked until a split with training positives is approved. The broader family-day "
                 "confound is analyzed in [`P2B_PROTOCOL_ANALYSIS.md`](P2B_PROTOCOL_ANALYSIS.md). "
                 "Detection remains **4/10** and no product claim changes.")
    lines.append("")
    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("venv/Scripts/python.exe scripts/volumetric_model.py \\")
    lines.append("  --output docs/VOLUMETRIC_MODEL.json \\")
    lines.append("  --report docs/VOLUMETRIC_DETECTOR.md")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run(output: str, report: str) -> dict[str, Any]:
    payload = build_payload()
    os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, allow_nan=False)
        handle.write("\n")
    os.makedirs(os.path.dirname(os.path.abspath(report)), exist_ok=True)
    with open(report, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(payload))
        handle.write("\n")
    print(f"wrote {output}", flush=True)
    print(f"wrote {report}", flush=True)
    return payload


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="docs/VOLUMETRIC_MODEL.json")
    parser.add_argument("--report", default="docs/VOLUMETRIC_DETECTOR.md")
    args = parser.parse_args(list(argv) if argv is not None else None)
    run(output=args.output, report=args.report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
