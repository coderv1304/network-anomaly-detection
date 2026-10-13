"""
create_samples.py
Extracts balanced/stratified sample subsets from raw CIC-IDS-2017 CSV files
and saves reproducible evaluation datasets into data/samples/.

Usage:
    python training/create_samples.py --output data/samples/sample_test.csv --samples-per-class 5000
"""

import os
import argparse
import pandas as pd
import numpy as np

DEFAULT_RAW_DIR = "data"
DEFAULT_OUTPUT_DIR = os.path.join("data", "samples")

CANDIDATE_FILES = [
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Monday-WorkingHours.pcap_ISCX.csv",
]

def load_and_sample(raw_dir=DEFAULT_RAW_DIR, output_dir=DEFAULT_OUTPUT_DIR, n_per_class=2000, random_state=42):
    os.makedirs(output_dir, exist_ok=True)
    sampled_frames = []
    encodings = ["utf-8", "latin1", "ISO-8859-1"]

    print(f"Scanning raw files in {raw_dir}...")
    for filename in CANDIDATE_FILES:
        filepath = os.path.join(raw_dir, filename)
        if not os.path.exists(filepath):
            continue

        print(f"Sampling from: {filename}")
        df = None
        for enc in encodings:
            try:
                df = pd.read_csv(filepath, encoding=enc, low_memory=False)
                break
            except Exception:
                continue

        if df is None:
            continue

        df.columns = df.columns.str.strip()
        if "Label" not in df.columns:
            continue

        # Clean inf and NaN
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(subset=["Label"], inplace=True)

        for label, group in df.groupby("Label"):
            take_n = min(len(group), n_per_class)
            sampled = group.sample(n=take_n, random_state=random_state)
            sampled_frames.append(sampled)

    if not sampled_frames:
        print("Warning: No raw CIC-IDS-2017 files found in 'data/' to sample from.")
        return

    combined = pd.concat(sampled_frames, ignore_index=True)
    combined = combined.sample(frac=1.0, random_state=random_state).reset_index(drop=True)

    out_path = os.path.join(output_dir, "test_dataset_sample.csv")
    combined.to_csv(out_path, index=False)
    print(f"Successfully generated sample dataset at {out_path} ({len(combined):,} rows)")
    print(f"Class breakdown:\n{combined['Label'].value_counts()}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create reproducible CIC-IDS-2017 sample CSVs.")
    parser.add_argument("--raw-dir", default=DEFAULT_RAW_DIR, help="Directory containing raw CSVs")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Destination directory for samples")
    parser.add_argument("--n-per-class", type=int, default=2000, help="Max samples per attack class")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    load_and_sample(args.raw_dir, args.output_dir, args.n_per_class, args.seed)
