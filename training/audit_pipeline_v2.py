"""Phase D2: audit CIC-IDS-2017 labels, features, splits, and leakage.

This audit is intentionally independent of the training pipeline's own
bookkeeping. It reads the source CSVs in chunks, hashes every source file,
canonicalizes labels for comparison, and reports:

* source SHA-256 and sizes;
* raw and canonical label distributions per file and per partition;
* rows with missing labels (including the all-blank trailer in the Thursday
  WebAttacks export);
* missing and infinite feature values;
* duplicate feature vectors within and across partitions;
* feature-name consistency, including pandas-mangled duplicate headers;
* unseen-family coverage for the day-based train/validation/test split;
* identifier columns and the preprocessing configuration.

Outputs:
    docs/DATA_PIPELINE_AUDIT.md
    docs/data_pipeline_audit.json
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import platform
import sys
import unicodedata
from datetime import UTC, datetime

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from training.evaluate import CIC_DAYS  # noqa: E402
from training.preprocessor import IDENTIFIER_COLUMNS  # noqa: E402

ENCODINGS = ["utf-8-sig", "cp1252", "latin1"]
CHUNK_ROWS = 120_000


def canonical_label(value) -> str:
    """Normalize a CIC label for comparison without changing its meaning."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return "<missing>"
    text = unicodedata.normalize("NFKC", str(value)).strip()
    for dash in ("\u2013", "\u2014", "\u2212"):
        text = text.replace(dash, "-")
    return " ".join(text.split())


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def detect_encoding(path: str) -> str:
    for encoding in ENCODINGS:
        try:
            pd.read_csv(path, nrows=200_000, encoding=encoding, low_memory=False)
            return encoding
        except UnicodeDecodeError:
            continue
        except Exception:
            return encoding
    return "latin1"


def raw_header_columns(path: str, encoding: str) -> list[str]:
    """Read the physical CSV header line, before pandas de-duplicates names.

    pandas silently renames a repeated header to ``name.1``, which hides the
    fact that the source file contains two columns with the same name.
    """
    with open(path, "rb") as handle:
        raw = handle.readline()
    return raw.decode(encoding, errors="replace").rstrip("\r\n").split(",")


def audit_file(path: str) -> dict:
    name = os.path.basename(path)
    encoding = detect_encoding(path)
    header = pd.read_csv(path, nrows=0, encoding=encoding)
    raw_columns = list(header.columns)
    physical_header = raw_header_columns(path, encoding)
    physical_stripped = [column.strip() for column in physical_header]
    raw_duplicate_headers = [
        column
        for column, count in collections.Counter(physical_stripped).items()
        if count > 1
    ]
    columns = [column.strip() for column in raw_columns]
    duplicate_headers = [
        column for column, count in collections.Counter(columns).items() if count > 1
    ]

    label_position = len(columns) - 1
    label_column = columns[label_position]
    feature_columns = [
        column for column in columns
        if column not in IDENTIFIER_COLUMNS and column != label_column
    ]

    raw_label_counts: collections.Counter = collections.Counter()
    canonical_label_counts: collections.Counter = collections.Counter()
    missing_label_rows = 0
    rows = 0
    rows_with_nan = 0
    rows_with_inf = 0
    per_column_nan: collections.Counter = collections.Counter()
    per_column_inf: collections.Counter = collections.Counter()
    negative_duration = 0
    zero_duration = 0
    hash_chunks: list[np.ndarray] = []

    for chunk in pd.read_csv(
        path,
        chunksize=CHUNK_ROWS,
        encoding=encoding,
        low_memory=False,
    ):
        chunk.columns = [column.strip() for column in chunk.columns]
        rows += len(chunk)

        labels = chunk[label_column]
        missing = labels.isna()
        missing_label_rows += int(missing.sum())
        for raw_value in labels[~missing].astype(str).tolist():
            raw_label_counts[raw_value] += 1
            canonical_label_counts[canonical_label(raw_value)] += 1

        features = chunk[feature_columns].apply(pd.to_numeric, errors="coerce")
        nan_mask = features.isna()
        inf_mask = np.isinf(features.to_numpy(dtype=float, na_value=np.nan))
        rows_with_nan += int(nan_mask.any(axis=1).sum())
        rows_with_inf += int(inf_mask.any(axis=1).sum())
        for column, count in nan_mask.sum().items():
            per_column_nan[column] += int(count)
        for index, column in enumerate(feature_columns):
            per_column_inf[column] += int(inf_mask[:, index].sum())

        if "Flow Duration" in features.columns:
            duration = features["Flow Duration"]
            negative_duration += int((duration < 0).sum())
            zero_duration += int((duration == 0).sum())

        hash_chunks.append(
            pd.util.hash_pandas_object(features, index=False).to_numpy(dtype=np.uint64)
        )

    hashes = (
        np.concatenate(hash_chunks) if hash_chunks else np.array([], dtype=np.uint64)
    )
    unique_hashes = np.unique(hashes)
    duplicate_rows = int(len(hashes) - len(unique_hashes))

    return {
        "file": name,
        "path": os.path.abspath(path),
        "sha256": sha256_file(path),
        "size_bytes": os.path.getsize(path),
        "encoding": encoding,
        "raw_columns": raw_columns,
        "physical_header": physical_header,
        "raw_duplicate_headers": raw_duplicate_headers,
        "columns": columns,
        "duplicate_headers": duplicate_headers,
        "label_column": label_column,
        "feature_columns": feature_columns,
        "feature_count": len(feature_columns),
        "rows": rows,
        "missing_label_rows": missing_label_rows,
        "raw_label_counts": dict(raw_label_counts),
        "canonical_label_counts": dict(canonical_label_counts),
        "rows_with_nan": rows_with_nan,
        "rows_with_inf": rows_with_inf,
        "per_column_nan": dict(per_column_nan),
        "per_column_inf": dict(per_column_inf),
        "negative_duration": negative_duration,
        "zero_duration": zero_duration,
        "duplicate_rows_within_file": duplicate_rows,
        "unique_feature_hashes": unique_hashes,
        "row_hashes": hashes,
    }


def _partition_hash_arrays(file_reports: list[dict], names: list[str]) -> np.ndarray:
    arrays = [report["unique_feature_hashes"] for report in file_reports if report["file"] in names]
    if not arrays:
        return np.array([], dtype=np.uint64)
    return np.concatenate(arrays)


def _partition_row_hashes(file_reports: list[dict], names: list[str]) -> np.ndarray:
    # For row-level leakage we need every row hash, not only unique values.
    # The per-file arrays are re-read from the cached report only when needed;
    # callers pass reports that already contain "row_hashes".
    arrays = [report["row_hashes"] for report in file_reports if report["file"] in names]
    if not arrays:
        return np.array([], dtype=np.uint64)
    return np.concatenate(arrays)


def summarize_partition(
    label: str,
    file_reports: list[dict],
    names: list[str],
    train_canonical_labels: set[str] | None,
) -> dict:
    reports = [report for report in file_reports if report["file"] in names]
    rows = sum(report["rows"] for report in reports)
    missing_labels = sum(report["missing_label_rows"] for report in reports)
    valid_rows = rows - missing_labels
    labels: collections.Counter = collections.Counter()
    for report in reports:
        labels.update(report["canonical_label_counts"])
    raw_labels: collections.Counter = collections.Counter()
    for report in reports:
        raw_labels.update(report["raw_label_counts"])

    unique_hashes = _partition_hash_arrays(file_reports, names)
    row_hashes = _partition_row_hashes(file_reports, names)
    duplicate_rows = int(len(row_hashes) - len(np.unique(row_hashes)))

    unseen = {}
    if train_canonical_labels is not None:
        unseen = {
            family: int(count)
            for family, count in labels.items()
            if family not in train_canonical_labels and family != "<missing>"
        }

    return {
        "partition": label,
        "files": names,
        "rows": rows,
        "rows_with_valid_label": valid_rows,
        "missing_label_rows": missing_labels,
        "label_counts": dict(labels),
        "raw_label_variants": dict(raw_labels),
        "unseen_families": unseen,
        "unseen_family_rows": int(sum(unseen.values())),
        "duplicate_rows_within_partition": duplicate_rows,
        "unique_feature_hashes": unique_hashes,
        "row_hashes": row_hashes,
    }


def cross_partition_leakage(source: dict, target: dict) -> dict:
    source_unique = np.unique(source["row_hashes"])
    target_rows = target["row_hashes"]
    overlap_rows = int(np.isin(target_rows, source_unique, assume_unique=False).sum())
    return {
        "source_partition": source["partition"],
        "target_partition": target["partition"],
        "overlapping_target_rows": overlap_rows,
        "overlap_pct_of_target": (
            overlap_rows / len(target_rows) * 100 if len(target_rows) else 0.0
        ),
    }


def feature_name_consistency(file_reports: list[dict]) -> dict:
    reference = None
    reference_name = None
    mismatches = []
    for report in file_reports:
        columns = report["columns"]
        if reference is None:
            reference = columns
            reference_name = report["file"]
            continue
        missing = sorted(set(reference) - set(columns))
        extra = sorted(set(columns) - set(reference))
        order_equal = columns == reference
        if missing or extra or not order_equal:
            mismatches.append({
                "file": report["file"],
                "missing_vs_reference": missing,
                "extra_vs_reference": extra,
                "same_order": order_equal,
            })
    return {
        "reference_file": reference_name,
        "reference_column_count": len(reference) if reference else 0,
        "mismatches": mismatches,
        "consistent": not mismatches,
    }


def build_report(data_dir: str, output_dir: str) -> dict:
    files = sorted(
        os.path.join(data_dir, name)
        for name in os.listdir(data_dir)
        if name.lower().endswith(".csv")
    )
    if not files:
        raise FileNotFoundError(f"No CSV files found in {data_dir}")

    file_reports = []
    for path in files:
        print(f"[audit] reading {os.path.basename(path)} ...", flush=True)
        report = audit_file(path)
        file_reports.append(report)

    train_names = CIC_DAYS["Monday"] + CIC_DAYS["Tuesday"]
    validation_names = CIC_DAYS["Wednesday"]
    test_names = CIC_DAYS["Thursday"] + CIC_DAYS["Friday"]

    all_names = {report["file"] for report in file_reports}
    configured_names = set(train_names + validation_names + test_names)
    unassigned = sorted(all_names - configured_names)
    missing_configured = sorted(configured_names - all_names)

    train_labels = set()
    for report in file_reports:
        if report["file"] in train_names:
            train_labels.update(report["canonical_label_counts"])

    partitions = [
        summarize_partition("train", file_reports, train_names, None),
        summarize_partition("validation", file_reports, validation_names, train_labels),
        summarize_partition("test", file_reports, test_names, train_labels),
    ]

    leakage = []
    for source in partitions:
        for target in partitions:
            if source["partition"] == target["partition"]:
                continue
            leakage.append(cross_partition_leakage(source, target))

    defects = []
    for report in file_reports:
        if report["raw_duplicate_headers"]:
            defects.append({
                "severity": "high",
                "area": "feature_names",
                "file": report["file"],
                "finding": (
                    "Duplicate physical CSV header(s) "
                    + ", ".join(report["raw_duplicate_headers"])
                    + "; pandas silently renames the later copy with a numeric "
                    "suffix (for example 'Fwd Header Length.1'), so the two "
                    "columns are indistinguishable in meaning but separate in "
                    "the feature schema."
                ),
            })
        if report["missing_label_rows"]:
            defects.append({
                "severity": "medium",
                "area": "labels",
                "file": report["file"],
                "finding": (
                    f"{report['missing_label_rows']:,} rows have a missing label "
                    "and are silently dropped by dropna(subset=['Label'])."
                ),
            })
        if report["rows_with_inf"]:
            defects.append({
                "severity": "medium",
                "area": "features",
                "file": report["file"],
                "finding": f"{report['rows_with_inf']:,} rows contain infinite feature values.",
            })
        if report["negative_duration"]:
            defects.append({
                "severity": "medium",
                "area": "features",
                "file": report["file"],
                "finding": f"{report['negative_duration']:,} rows have a negative Flow Duration.",
            })

    for item in leakage:
        if item["overlapping_target_rows"]:
            defects.append({
                "severity": "high",
                "area": "split_leakage",
                "file": "-",
                "finding": (
                    f"{item['overlapping_target_rows']:,} rows in "
                    f"{item['target_partition']} duplicate a feature vector in "
                    f"{item['source_partition']} ({item['overlap_pct_of_target']:.3f}% "
                    "of the target partition)."
                ),
            })

    if unassigned:
        defects.append({
            "severity": "low",
            "area": "split_coverage",
            "file": "-",
            "finding": "CSV files not assigned to any partition: " + ", ".join(unassigned),
        })

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "data_dir": os.path.abspath(data_dir),
        "python_version": platform.python_version(),
        "pandas_version": pd.__version__,
        "numpy_version": np.__version__,
        "split_rule": {
            "train": train_names,
            "validation": validation_names,
            "test": test_names,
        },
        "identifier_columns": IDENTIFIER_COLUMNS,
        "preprocessing": {
            "label_vocabulary": "fit on training partition only",
            "imputer": "SimpleImputer(strategy='median') fit on training partition only",
            "scaler": "StandardScaler fit on training partition only",
            "infinity_handling": "FlowSanitizer replaces +/-inf with NaN before imputation",
            "deduplication": "within each partition only (day_based loader)",
            "feature_order": "first training file order, identifiers removed",
        },
        "feature_name_consistency": feature_name_consistency(file_reports),
        "files": [
            {
                key: value
                for key, value in report.items()
                if key not in {"row_hashes", "unique_feature_hashes"}
            }
            for report in file_reports
        ],
        "partitions": [
            {
                key: value
                for key, value in partition.items()
                if key not in {"row_hashes", "unique_feature_hashes"}
            }
            for partition in partitions
        ],
        "cross_partition_leakage": leakage,
        "unassigned_files": unassigned,
        "missing_configured_files": missing_configured,
        "confirmed_defects": defects,
    }
    return report


def write_markdown(report: dict, path: str) -> None:
    lines = [
        "# Data, Label, Feature, and Split Audit (Phase D2)",
        "",
        f"*Generated: {report['generated_at']}*",
        f"*Data directory: `{report['data_dir']}`*",
        "",
        "## 1. Split rule",
        "",
        "| Partition | Source files |",
        "| --- | --- |",
    ]
    for partition, files in report["split_rule"].items():
        lines.append(f"| {partition} | {', '.join(f'`{name}`' for name in files)} |")

    lines.extend([
        "",
        "## 2. Source files",
        "",
        "| File | Rows | Encoding | SHA-256 | Size (MiB) |",
        "| --- | ---: | --- | --- | ---: |",
    ])
    for item in report["files"]:
        lines.append(
            f"| `{item['file']}` | {item['rows']:,} | {item['encoding']} | "
            f"`{item['sha256']}` | {item['size_bytes'] / 1024 / 1024:.1f} |"
        )

    lines.extend([
        "",
        "## 3. Class distribution per partition",
        "",
        "| Partition | Valid rows | Missing labels | Families |",
        "| --- | ---: | ---: | ---: |",
    ])
    for partition in report["partitions"]:
        families = len([key for key in partition["label_counts"] if key != "<missing>"])
        lines.append(
            f"| {partition['partition']} | {partition['rows_with_valid_label']:,} | "
            f"{partition['missing_label_rows']:,} | {families} |"
        )

    for partition in report["partitions"]:
        lines.extend([
            "",
            f"### {partition['partition'].title()} label counts",
            "",
            "| Canonical label | Rows |",
            "| --- | ---: |",
        ])
        for label, count in sorted(
            partition["label_counts"].items(), key=lambda item: item[1], reverse=True
        ):
            lines.append(f"| {label} | {count:,} |")
        if partition["unseen_families"]:
            lines.extend([
                "",
                "Unseen families (present here, absent from training):",
                "",
                "| Family | Rows |",
                "| --- | ---: |",
            ])
            for family, count in sorted(
                partition["unseen_families"].items(), key=lambda item: item[1], reverse=True
            ):
                lines.append(f"| {family} | {count:,} |")

    lines.extend([
        "",
        "## 4. Missing and infinite values",
        "",
        "| File | Rows with NaN | Rows with Inf | Negative duration | Zero duration |",
        "| --- | ---: | ---: | ---: | ---: |",
    ])
    for item in report["files"]:
        lines.append(
            f"| `{item['file']}` | {item['rows_with_nan']:,} | {item['rows_with_inf']:,} | "
            f"{item['negative_duration']:,} | {item['zero_duration']:,} |"
        )

    lines.extend([
        "",
        "## 5. Duplicates and leakage",
        "",
        "| File | Duplicate feature rows |",
        "| --- | ---: |",
    ])
    for item in report["files"]:
        lines.append(
            f"| `{item['file']}` | {item['duplicate_rows_within_file']:,} |"
        )
    lines.extend([
        "",
        "| Source partition | Target partition | Overlapping target rows | % of target |",
        "| --- | --- | ---: | ---: |",
    ])
    for item in report["cross_partition_leakage"]:
        lines.append(
            f"| {item['source_partition']} | {item['target_partition']} | "
            f"{item['overlapping_target_rows']:,} | {item['overlap_pct_of_target']:.3f}% |"
        )

    lines.extend([
        "",
        "## 6. Feature-name consistency",
        "",
        f"Reference file: `{report['feature_name_consistency']['reference_file']}` "
        f"({report['feature_name_consistency']['reference_column_count']} columns).",
        "",
    ])
    physical_duplicates = {
        item["file"]: item["raw_duplicate_headers"]
        for item in report["files"]
        if item["raw_duplicate_headers"]
    }
    if physical_duplicates:
        lines.append(
            "Physical CSV headers contain duplicate names (pandas appends a "
            "numeric suffix on read):"
        )
        lines.append("")
        for name, headers in physical_duplicates.items():
            lines.append(f"- `{name}`: {', '.join(f'`{h}`' for h in headers)}")
        lines.append("")
    if report["feature_name_consistency"]["consistent"]:
        lines.append("All source files expose the same stripped column names in the same order.")
    else:
        for mismatch in report["feature_name_consistency"]["mismatches"]:
            lines.append(
                f"- `{mismatch['file']}`: missing={mismatch['missing_vs_reference']}, "
                f"extra={mismatch['extra_vs_reference']}, same_order={mismatch['same_order']}"
            )

    lines.extend([
        "",
        "## 7. Confirmed defects",
        "",
    ])
    if report["confirmed_defects"]:
        lines.extend([
            "| Severity | Area | File | Finding |",
            "| --- | --- | --- | --- |",
        ])
        for defect in report["confirmed_defects"]:
            lines.append(
                f"| {defect['severity']} | {defect['area']} | `{defect['file']}` | "
                f"{defect['finding']} |"
            )
    else:
        lines.append("No defects were detected by this audit.")

    lines.extend([
        "",
        "## 8. Preprocessing configuration",
        "",
        "| Setting | Value |",
        "| --- | --- |",
    ])
    for key, value in report["preprocessing"].items():
        lines.append(f"| {key} | {value} |")

    lines.extend([
        "",
        "## 9. Reproduce",
        "",
        "```bash",
        "venv/Scripts/python.exe training/audit_pipeline_v2.py --data-dir data --output-dir docs",
        "```",
        "",
    ])

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit labels, features, splits, and leakage.")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--output-dir", default="docs")
    args = parser.parse_args()

    report = build_report(args.data_dir, args.output_dir)
    json_path = os.path.join(args.output_dir, "data_pipeline_audit.json")
    md_path = os.path.join(args.output_dir, "DATA_PIPELINE_AUDIT.md")
    os.makedirs(args.output_dir, exist_ok=True)
    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, default=str)
    write_markdown(report, md_path)
    print(f"[audit] wrote {json_path}")
    print(f"[audit] wrote {md_path}")


if __name__ == "__main__":
    main()
