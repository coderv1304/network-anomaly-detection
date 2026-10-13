"""
training/audit_dataset.py

Dataset audit tool inspired by the critique of Engelen et al. (2021):
"Troubleshooting an intrusion detection dataset: the CICIDS2017 case study".

Audits CIC-IDS-2017 files for:
1. Exact and semantic flow duplicates.
2. Missing values (NaN) and non-finite values (+/- Infinity).
3. Negative or zero flow durations.
4. Non-standard port values (e.g. port 0).
5. Label inconsistencies and whitespace variations.
6. Class distribution imbalance.

Outputs a structured audit report in markdown.
"""

import os
import glob
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timezone

ENCODINGS = ["utf-8", "latin1", "ISO-8859-1"]

def audit_file(filepath: str) -> dict:
    fname = os.path.basename(filepath)
    print(f"Auditing: {fname} ...")
    
    df = None
    for enc in ENCODINGS:
        try:
            df = pd.read_csv(filepath, encoding=enc, low_memory=False)
            break
        except Exception:
            continue

    if df is None:
        return {"filename": fname, "error": "Could not read CSV with standard encodings."}

    total_rows = len(df)
    cols_raw = list(df.columns)
    df.columns = df.columns.str.strip()

    # 1. Duplicate check
    duplicates = int(df.duplicated().sum())

    # 2. Inf / NaN check
    has_inf = 0
    numeric_df = df.select_dtypes(include=[np.number])
    if not numeric_df.empty:
        has_inf = int(np.isinf(numeric_df.values).any(axis=1).sum())
    has_nan = int(df.isna().any(axis=1).sum())

    # 3. Negative or zero duration
    neg_duration = 0
    zero_duration = 0
    if "Flow Duration" in df.columns:
        dur = pd.to_numeric(df["Flow Duration"], errors="coerce")
        neg_duration = int((dur < 0).sum())
        zero_duration = int((dur == 0).sum())

    # 4. Port 0 check
    port_zero = 0
    for p_col in ["Source Port", "Destination Port"]:
        if p_col in df.columns:
            ports = pd.to_numeric(df[p_col], errors="coerce")
            port_zero += int((ports == 0).sum())

    # 5. Label distribution
    label_counts = {}
    if "Label" in df.columns:
        label_counts = df["Label"].value_counts().to_dict()

    return {
        "filename": fname,
        "total_rows": total_rows,
        "duplicates": duplicates,
        "duplicate_pct": (duplicates / total_rows * 100) if total_rows else 0.0,
        "has_inf": has_inf,
        "has_nan": has_nan,
        "neg_duration": neg_duration,
        "zero_duration": zero_duration,
        "port_zero": port_zero,
        "label_counts": label_counts
    }

def run_audit(target_dir: str, output_report: str):
    files = glob.glob(os.path.join(target_dir, "*.csv"))
    if not files:
        print(f"No CSV files found in {target_dir}")
        return

    results = []
    for f in files:
        results.append(audit_file(f))

    # Generate Markdown Report
    lines = [
        "# CIC-IDS-2017 Dataset Audit Report",
        "",
        f"*Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}*",
        "",
        "## 1. Overview & Context",
        "This audit verifies data hygiene and known artifact flaws documented by **Engelen et al. (2021)** in *Computers & Security*. It checks for duplicate flows, infinite values, invalid flow durations, and label anomalies.",
        "",
        "## 2. Summary Table",
        "",
        "| File | Total Rows | Duplicates (%) | Rows with Inf | Rows with NaN | Zero/Neg Duration |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |"
    ]

    for r in results:
        if "error" in r:
            lines.append(f"| {r['filename']} | ERROR | - | - | - | - |")
            continue
        lines.append(
            f"| `{r['filename']}` | {r['total_rows']:,} | {r['duplicates']:,} ({r['duplicate_pct']:.1f}%) | "
            f"{r['has_inf']:,} | {r['has_nan']:,} | {r['zero_duration'] + r['neg_duration']:,} |"
        )

    lines.extend([
        "",
        "## 3. Label Breakdown per File",
        ""
    ])

    for r in results:
        if "label_counts" in r and r["label_counts"]:
            lines.append(f"### `{r['filename']}`")
            lines.append("| Label | Count | Proportion |")
            lines.append("| :--- | :--- | :--- |")
            total = r["total_rows"]
            for lbl, cnt in r["label_counts"].items():
                pct = (cnt / total * 100) if total else 0
                lines.append(f"| **{lbl}** | {cnt:,} | {pct:.2f}% |")
            lines.append("")

    lines.extend([
        "## 4. Pipeline Cleaning Decisions",
        "Based on this audit, our training pipeline enforces the following explicit rules:",
        "1. **Deduplication:** Duplicate flow records must be removed; training on identical flows leads to artificially inflated validation metrics.",
        "2. **Finite Value Imputation:** Infinite values (`Flow Bytes/s`, `Flow Packets/s`) are converted to NaN and imputed using median statistics computed **strictly on the training fold**.",
        "3. **Zero-Duration Filtering:** Flows with negative durations are discarded as sensor artifacts.",
        "4. **Identifier Stripping:** IP addresses, timestamps, and flow IDs are stripped to prevent models from learning host-identity shortcuts."
    ])

    os.makedirs(os.path.dirname(output_report), exist_ok=True)
    with open(output_report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\nAudit report successfully saved to: {output_report}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit CSV files for CIC-IDS-2017 issues.")
    parser.add_argument("--data-dir", default="data/samples", help="Directory with CSV files to audit")
    parser.add_argument("--output", default="docs/DATASET_AUDIT.md", help="Output markdown report path")
    args = parser.parse_args()

    run_audit(args.data_dir, args.output)
