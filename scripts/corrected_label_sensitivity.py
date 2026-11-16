#!/usr/bin/env python
"""P3C corrected-label sensitivity on the DistriNet CIC-IDS-2017 release.

The DistriNet release is a re-extraction with corrected CICFlowMeter flow
boundaries *and* revised label strings. This script applies the frozen label
policy strictly, trains the same portable-ratio Random Forest used by P3B on
the corrected CSVs, and reports the in-distribution result next to the P3B
original-Kaggle arm.

Policy (chosen before this run):
- Map only case/dash/spelling variants of labels already in the frozen policy
  (``Portscan`` -> ``PortScan``, ``Botnet`` -> ``Bot``, and similar).
- Exclude every ``- Attempted`` label and ``Infiltration - Portscan``. The
  frozen policy has no attempted category, so treating attempted rows as
  positives would be a new policy rather than a sensitivity run.
- Exclude the frozen non-target families (web attacks, credential attacks,
  botnet, infiltration, Heartbleed) for the same reason.

This is an in-distribution label/extraction sensitivity. It does not score an
external dataset, does not tune on external labels, does not touch the serving
artifact, and does not change any existing report.

Example:
    venv/Scripts/python.exe scripts/corrected_label_sensitivity.py \
        --dir data/CICIDS2017_improved
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import sys
from collections import Counter
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scripts.cross_dataset_transfer import (  # noqa: E402
    coverage_gate,
    metrics_at_threshold,
    partition_counts,
    ranking_metrics,
    stratified_group_split,
)
from scripts.rule_baselines import (  # noqa: E402
    EXCLUDED_LABELS,
    NEGATIVE_LABELS,
    POSITIVE_LABELS,
    select_budget_threshold,
)
from training.baseline_comparison_v2 import canonical_label  # noqa: E402
from training.portable_features import (  # noqa: E402
    portable_matrix,
    schema_payload,
)

SEED = 42
BUDGETS = (10, 100)
DIRECTORY = "data/CICIDS2017_improved"
RESULTS_JSON = os.path.join(PROJECT_ROOT, "docs", "corrected_label_sensitivity.json")
REPORT = os.path.join(PROJECT_ROOT, "docs", "CORRECTED_LABEL_SENSITIVITY.md")
BASELINE_RESULTS = os.path.join(PROJECT_ROOT, "docs", "portable_transfer_results.json")

SOURCE_COLUMNS = {
    "fwd_packets": "Total Fwd Packet",
    "bwd_packets": "Total Bwd packets",
    "fwd_bytes": "Total Length of Fwd Packet",
    "bwd_bytes": "Total Length of Bwd Packet",
}
GROUP_COLUMNS = ("Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol")

# The corrected release changed case/spelling only for these labels. Values are
# exact frozen-policy names. Anything else is left unchanged and then resolved
# by the frozen positive/negative/excluded sets.
LABEL_ALIASES = {
    "Portscan": "PortScan",
    "Botnet": "Bot",
    "DoS Slowloris": "DoS slowloris",
    "Web Attack - SQL Injection": "Web Attack - Sql Injection",
}

# Corrected-release categories that the frozen policy does not define. They are
# excluded explicitly so they cannot silently fall into an "unknown" bucket.
EXCLUDED_ALIASES = {
    "Infiltration - Portscan": "corrected-release portscan category; not in frozen policy",
}

LIMITS = [
    "The corrected release is both a relabelling and a re-extraction with a fixed CICFlowMeter. A difference from the original Kaggle arm cannot be attributed to labels alone.",
    "The strict policy excludes every `- Attempted` row. That is a policy choice, not evidence that attempted attacks are harmless.",
    "This is an in-distribution sensitivity under the P3B stratified-group protocol. It does not report external transfer and does not establish deployability.",
    "The serving artifact, the frozen Tier A schema, and every existing claim are unchanged.",
]


def corrected_role(raw: Any) -> dict[str, Any]:
    """Return the strict frozen-policy role for one corrected-release label."""
    canonical = canonical_label(raw)
    if canonical == "<missing>" or not canonical.strip():
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": "<missing>",
            "role": "excluded",
            "reason": "missing label",
        }
    if canonical.endswith(" - Attempted"):
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": canonical,
            "role": "excluded",
            "reason": "attempted variant; strict frozen policy excludes",
        }
    mapped = LABEL_ALIASES.get(canonical, canonical)
    if mapped in EXCLUDED_ALIASES:
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": mapped,
            "role": "excluded",
            "reason": EXCLUDED_ALIASES[mapped],
        }
    if mapped in NEGATIVE_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": mapped,
            "role": "negative",
            "reason": "benign traffic",
        }
    if mapped in POSITIVE_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": mapped,
            "role": "positive",
            "reason": "volumetric or scanning family",
        }
    if mapped in EXCLUDED_LABELS:
        return {
            "raw": raw,
            "canonical": canonical,
            "mapped": mapped,
            "role": "excluded",
            "reason": EXCLUDED_LABELS[mapped],
        }
    return {
        "raw": raw,
        "canonical": canonical,
        "mapped": mapped,
        "role": "excluded",
        "reason": "unknown label; not mapped by strict policy",
    }


def load_corrected(
    directory: str,
    max_rows_per_file: int | None = None,
    chunksize: int = 200_000,
) -> dict[str, Any]:
    """Load the corrected CSVs under the strict policy and build portable features."""
    files = sorted(
        os.path.join(directory, name)
        for name in os.listdir(directory)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"no CSV files in {directory}")

    matrices: list[np.ndarray] = []
    truths: list[np.ndarray] = []
    families: list[np.ndarray] = []
    group_hashes: list[np.ndarray] = []
    raw_counts: Counter[str] = Counter()
    kept_counts: Counter[str] = Counter()
    role_counts: Counter[str] = Counter()
    excluded_reasons: Counter[str] = Counter()
    file_rows: dict[str, int] = {}
    invalid_input_rows = 0
    total_rows = 0

    for path in files:
        rows = 0
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            chunk.columns = [
                str(column).strip().lstrip("\ufeff") for column in chunk.columns
            ]
            if max_rows_per_file is not None:
                remaining = max_rows_per_file - rows
                if remaining <= 0:
                    break
                chunk = chunk.head(remaining)
            if chunk.empty:
                continue
            rows += len(chunk)
            raw_counts.update(chunk["Label"].astype(str).tolist())

            decisions = [corrected_role(value) for value in chunk["Label"].tolist()]
            roles = np.asarray([item["role"] for item in decisions], dtype=object)
            mapped = np.asarray([item["mapped"] for item in decisions], dtype=object)
            role_counts.update(roles.tolist())
            for item, role in zip(decisions, roles):
                if role == "excluded":
                    excluded_reasons[item["reason"]] += 1

            keep = (roles == "positive") | (roles == "negative")
            if not keep.any():
                continue
            sub = chunk.loc[keep]
            labels = mapped[keep]
            truth = (roles[keep] == "positive").astype(np.int8)
            values = (
                sub[list(SOURCE_COLUMNS.values())]
                .apply(pd.to_numeric, errors="coerce")
                .to_numpy(dtype=np.float64)
            )
            invalid_input_rows += int(
                np.sum(~np.isfinite(values).all(axis=1) | (values < 0.0).any(axis=1))
            )
            matrix = portable_matrix(values[:, 0], values[:, 1], values[:, 2], values[:, 3])

            key_frame = sub[list(GROUP_COLUMNS)].astype(str).reset_index(drop=True)
            key_frame["__family"] = labels
            hashes = pd.util.hash_pandas_object(key_frame, index=False).to_numpy(
                dtype=np.uint64
            )

            matrices.append(matrix)
            truths.append(truth)
            families.append(labels)
            group_hashes.append(hashes)
            kept_counts.update(labels.tolist())

        file_rows[os.path.basename(path)] = rows
        total_rows += rows
        gc.collect()

    if not matrices:
        raise RuntimeError("no rows survived the strict label policy")

    matrix = np.concatenate(matrices, axis=0)
    truth = np.concatenate(truths)
    family_array = np.concatenate(families)
    hashes = np.concatenate(group_hashes)
    return {
        "directory": os.path.relpath(directory, PROJECT_ROOT).replace("\\", "/"),
        "files": file_rows,
        "rows_read": total_rows,
        "rows_kept": int(matrix.shape[0]),
        "prevalence": float(truth.mean()) if truth.size else None,
        "matrix": matrix,
        "truth": truth,
        "families": family_array,
        "group_hashes": hashes,
        "raw_label_counts": dict(sorted(raw_counts.items())),
        "kept_label_counts": dict(sorted(kept_counts.items())),
        "role_counts": dict(sorted(role_counts.items())),
        "excluded_reasons": dict(sorted(excluded_reasons.items())),
        "invalid_input_rows": invalid_input_rows,
        "portable_schema": schema_payload(),
    }


def train_and_evaluate(data: dict[str, Any]) -> dict[str, Any]:
    """Train the P3B model on corrected rows and evaluate the grouped split."""
    split = stratified_group_split(data["group_hashes"], data["families"], seed=SEED)
    partition = split["partition"]
    counts = partition_counts(partition, data["families"])
    gate = coverage_gate(counts)
    if not gate["overall_pass"]:
        raise RuntimeError(f"training split fails the coverage gate: {gate['reason']}")

    train_mask = partition == 0
    validation_mask = partition == 1
    test_mask = partition == 2
    if not (train_mask.any() and validation_mask.any() and test_mask.any()):
        raise RuntimeError("grouped split produced an empty partition")

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
    thresholds = {
        f"{budget}_per_10k": select_budget_threshold(validation_scores, budget)
        for budget in BUDGETS
    }

    in_distribution = []
    for name, mask in (
        ("train", train_mask),
        ("validation", validation_mask),
        ("test", test_mask),
    ):
        scores = 1.0 - classifier.predict_proba(data["matrix"][mask])[:, benign_index]
        ranking = ranking_metrics(scores, data["truth"][mask])
        in_distribution.append(
            {
                "partition": name,
                "rows": int(mask.sum()),
                "positives": int(data["truth"][mask].sum()),
                "roc_auc": ranking["roc_auc"],
                "average_precision": ranking["average_precision"],
            }
        )

    family_names = ["Benign"] + sorted(
        name for name in np.unique(data["families"]) if name != "BENIGN"
    )
    family_codes = np.zeros(len(data["families"]), dtype=np.int64)
    for code, name in enumerate(family_names):
        if name == "Benign":
            family_codes[data["families"] == "BENIGN"] = code
        else:
            family_codes[data["families"] == name] = code

    test_scores = 1.0 - classifier.predict_proba(data["matrix"][test_mask])[
        :, benign_index
    ]
    results = {}
    for budget, selected in thresholds.items():
        results[budget] = metrics_at_threshold(
            test_scores,
            data["truth"][test_mask],
            family_codes[test_mask],
            family_names,
            selected["threshold"],
        )

    return {
        "split": {key: value for key, value in split.items() if key != "partition"},
        "partitions": counts,
        "coverage_gate": gate,
        "thresholds": thresholds,
        "in_distribution": in_distribution,
        "results": results,
        "test_scores": test_scores,
        "test_prevalence": float(data["truth"][test_mask].mean()),
        "benign_class_index": benign_index,
    }


def _baseline() -> dict[str, Any]:
    if not os.path.isfile(BASELINE_RESULTS):
        return {}
    with open(BASELINE_RESULTS, encoding="utf-8") as handle:
        payload = json.load(handle)
    test_row = next(
        (row for row in payload.get("in_distribution", []) if row["partition"] == "test"),
        {},
    )
    test_counts = payload.get("training", {}).get("partitions", {}).get("test", {})
    test_rows = sum(test_counts.values()) or None
    test_positives = sum(
        count for name, count in test_counts.items() if name != "BENIGN"
    )
    return {
        "source": os.path.relpath(BASELINE_RESULTS, PROJECT_ROOT).replace("\\", "/"),
        "model_sha256": payload.get("model_sha256"),
        "test": test_row,
        "test_prevalence": (
            test_positives / test_rows if test_rows else None
        ),
        "thresholds": payload.get("thresholds", {}),
    }


def run(
    directory: str,
    output: str = RESULTS_JSON,
    report: str = REPORT,
    max_rows_per_file: int | None = None,
) -> dict[str, Any]:
    data = load_corrected(directory, max_rows_per_file=max_rows_per_file)
    trained = train_and_evaluate(data)
    payload = {
        "artifact_version": "corrected-label-sensitivity-v1",
        "status": "PARTIAL" if max_rows_per_file else "COMPLETE",
        "method": "strict_frozen_policy_corrected_release_in_distribution",
        "scope": (
            "In-distribution sensitivity only. Not an external-transfer result "
            "and not a deployability claim."
        ),
        "source": {
            "directory": data["directory"],
            "files": data["files"],
            "provenance": "docs/DISTRINET_CICIDS2017_AUDIT.json",
        },
        "policy": {
            "description": "Strict frozen policy; case/spelling variants only.",
            "aliases": LABEL_ALIASES,
            "excluded_aliases": EXCLUDED_ALIASES,
            "attempted": "excluded",
            "positive_labels": sorted(POSITIVE_LABELS),
            "negative_labels": sorted(NEGATIVE_LABELS),
            "excluded_labels": dict(sorted(EXCLUDED_LABELS.items())),
        },
        "data": {
            "rows_read": data["rows_read"],
            "rows_kept": data["rows_kept"],
            "prevalence": data["prevalence"],
            "raw_label_counts": data["raw_label_counts"],
            "kept_label_counts": data["kept_label_counts"],
            "role_counts": data["role_counts"],
            "excluded_reasons": data["excluded_reasons"],
            "invalid_input_rows": data["invalid_input_rows"],
            "portable_schema": data["portable_schema"],
        },
        "training": {
            "seed": SEED,
            "split_mode": "stratified_group",
            "fractions": (0.70, 0.15, 0.15),
            "partitions": trained["partitions"],
            "test_prevalence": trained["test_prevalence"],
            "coverage_gate": trained["coverage_gate"],
            "split": trained["split"],
            "model": "RandomForestClassifier(n_estimators=200, seed=42)",
        },
        "thresholds": trained["thresholds"],
        "in_distribution": trained["in_distribution"],
        "results": trained["results"],
        "baseline_original_kaggle": _baseline(),
        "interpretation": _interpret(data, trained, _baseline()),
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


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{100.0 * float(value):.4f}%"


def _num(value: float | None) -> str:
    return "—" if value is None else f"{float(value):.4f}"


def _delta(new: float | None, old: float | None) -> str:
    if new is None or old is None:
        return "—"
    return f"{float(new) - float(old):+.4f}"


def _interpret(
    data: dict[str, Any],
    trained: dict[str, Any],
    baseline: dict[str, Any],
) -> str:
    test_row = next(
        (row for row in trained["in_distribution"] if row["partition"] == "test"),
        {},
    )
    old = baseline.get("test", {})
    parts = [
        f"The corrected release kept {data['rows_kept']:,} of "
        f"{data['rows_read']:,} rows under the strict policy "
        f"({_pct(data['prevalence'])} positive).",
        f"On the grouped test partition the portable model reached ROC-AUC "
        f"{_num(test_row.get('roc_auc'))} and average precision "
        f"{_num(test_row.get('average_precision'))}.",
    ]
    if old:
        parts.append(
            f"The original-Kaggle P3B arm reached ROC-AUC {_num(old.get('roc_auc'))} "
            f"and average precision {_num(old.get('average_precision'))} under the "
            f"same split algorithm; the corrected-arm deltas are "
            f"{_delta(test_row.get('roc_auc'), old.get('roc_auc'))} and "
            f"{_delta(test_row.get('average_precision'), old.get('average_precision'))}."
        )
    old_prevalence = baseline.get("test_prevalence")
    new_prevalence = trained.get("test_prevalence")
    if old_prevalence is not None and new_prevalence is not None:
        parts.append(
            f"Test prevalence was {_pct(old_prevalence)} in the original arm and "
            f"{_pct(new_prevalence)} in the corrected arm; average precision is "
            "prevalence-sensitive, so the AP comparison needs that context."
        )
    saturated = [
        budget
        for budget, selected in trained["thresholds"].items()
        if float(selected.get("threshold", 0.0)) >= 1.0 - 1e-12
    ]
    if saturated:
        parts.append(
            f"The validation-selected threshold saturated at 1.000000 for "
            f"{', '.join(saturated)}; strict test alerts are therefore zero by "
            "construction, not a measured false-positive rate."
        )
    parts.append(
        "Because the corrected release is also a CICFlowMeter re-extraction, a "
        "difference cannot be attributed to labels alone. This is a sensitivity "
        "check, not a replacement for the original result and not external evidence."
    )
    return " ".join(parts)


def render_report(payload: dict[str, Any]) -> str:
    lines = [
        "# Corrected-Label Sensitivity (P3C)",
        "",
        f"**Status:** **{payload['status']}**",
        "**Scope:** in-distribution sensitivity on the DistriNet CIC-IDS-2017 release. Not an external-transfer result.",
        "",
        "This is a **separate research check**. It does not modify the serving",
        "artifact, the frozen Tier A schema, the P3B artifact, or any existing",
        "claim.",
        "",
        "## 1. Label policy",
        "",
        "The strict frozen policy was applied before any model was trained:",
        "",
        "- Case/spelling aliases only: "
        + ", ".join(
            f"`{source}` -> `{target}`"
            for source, target in payload["policy"]["aliases"].items()
        )
        + ".",
        "- Every `- Attempted` label is excluded. The frozen policy has no",
        "  attempted category, so treating attempted rows as positives would be",
        "  a new policy rather than a sensitivity run.",
        "- `Infiltration - Portscan` and every frozen non-target family are",
        "  excluded for the same reason.",
        "",
        "## 2. Data under the policy",
        "",
        f"- Rows read: **{payload['data']['rows_read']:,}**",
        f"- Rows kept: **{payload['data']['rows_kept']:,}**",
        f"- Prevalence: **{_pct(payload['data']['prevalence'])}**",
        f"- Rows with non-finite/negative portable inputs: "
        f"**{payload['data']['invalid_input_rows']:,}** (cleaned to 0 by the fixed transform)",
        "",
        "| Kept label | Rows |",
        "| --- | ---: |",
    ]
    for label, count in payload["data"]["kept_label_counts"].items():
        lines.append(f"| `{label}` | {count:,} |")
    lines.extend(
        [
            "",
            "| Excluded reason | Rows |",
            "| --- | ---: |",
        ]
    )
    for reason, count in payload["data"]["excluded_reasons"].items():
        lines.append(f"| {reason} | {count:,} |")
    lines.extend(
        [
            "",
            "> The corrected release is also a re-extraction with fixed",
            "> CICFlowMeter flow boundaries. Differences below are therefore",
            "> **label + extraction**, not label-only.",
            "",
            "## 3. Split and model",
            "",
            "- Stratified group split, 70/15/15, seed 42.",
            "- Random Forest, 200 trees, seed 42.",
            "- Thresholds selected only on the validation partition.",
            "",
            "| Partition | Rows | Positives |",
            "| --- | ---: | ---: |",
        ]
    )
    for row in payload["in_distribution"]:
        lines.append(
            f"| {row['partition']} | {row['rows']:,} | {row['positives']:,} |"
        )
    lines.extend(
        [
            "",
            f"Coverage gate: **{'PASS' if payload['training']['coverage_gate']['overall_pass'] else 'FAIL'}**.",
            "",
            "## 4. In-distribution result",
            "",
            "| Partition | ROC-AUC | Average precision |",
            "| --- | ---: | ---: |",
        ]
    )
    for row in payload["in_distribution"]:
        lines.append(
            f"| {row['partition']} | {_num(row['roc_auc'])} | "
            f"{_num(row['average_precision'])} |"
        )
    lines.extend(
        [
            "",
            "## 5. Validation thresholds and test behavior",
            "",
            "| Budget | Threshold | Alerts | TP | FP | Recall | FPR | PPV |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for budget, selected in payload["thresholds"].items():
        row = payload["results"][budget]
        lines.append(
            f"| {budget} | {_num(selected['threshold'])} | "
            f"{row['tp'] + row['fp']:,} | {row['tp']:,} | {row['fp']:,} | "
            f"{_pct(row['recall'])} | {_pct(row['fpr'])} | {_pct(row['ppv'])} |"
        )
    lines.extend(
        [
            "",
            "### Per-family recall at 100 alerts/10k",
            "",
            "| Family | Rows | Detected | Recall |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    for family, row in payload["results"]["100_per_10k"]["per_family"].items():
        lines.append(
            f"| `{family}` | {row['rows']:,} | {row['detected']:,} | "
            f"{_pct(row['recall'])} |"
        )
    lines.extend(
        [
            "",
            "## 6. Comparison with the original-Kaggle P3B arm",
            "",
            "| Metric | P3B original | P3C corrected | Delta |",
            "| --- | ---: | ---: | ---: |",
        ]
    )
    baseline = payload["baseline_original_kaggle"].get("test", {})
    test_row = next(
        (row for row in payload["in_distribution"] if row["partition"] == "test"),
        {},
    )
    for label, key in (
        ("ROC-AUC", "roc_auc"),
        ("Average precision", "average_precision"),
    ):
        lines.append(
            f"| {label} | {_num(baseline.get(key))} | {_num(test_row.get(key))} | "
            f"{_delta(test_row.get(key), baseline.get(key))} |"
        )
    lines.append(
        f"| Test prevalence | {_pct(payload['baseline_original_kaggle'].get('test_prevalence'))} "
        f"| {_pct(payload['training'].get('test_prevalence'))} | — |"
    )
    lines.extend(
        [
            "",
            "## 7. Interpretation",
            "",
            payload["interpretation"],
            "",
            "## 8. What this does not prove",
            "",
        ]
    )
    for item in payload["limits"]:
        lines.append(f"- {item}")
    lines.extend(
        [
            "",
            "## 9. Reproduction",
            "",
            "```bash",
            "venv/Scripts/python.exe scripts/corrected_label_sensitivity.py \\",
            "  --dir data/CICIDS2017_improved",
            "venv/Scripts/python.exe -m pytest tests/test_corrected_label_sensitivity.py -q",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default=DIRECTORY)
    parser.add_argument("--output", default=RESULTS_JSON)
    parser.add_argument("--report", default=REPORT)
    parser.add_argument("--max-rows-per-file", type=int, default=None)
    args = parser.parse_args(argv)
    run(
        args.dir,
        output=args.output,
        report=args.report,
        max_rows_per_file=args.max_rows_per_file,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
