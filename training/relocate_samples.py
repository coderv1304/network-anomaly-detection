"""
relocate_samples.py
One-time migration script for Phase 0 repo hygiene.
Moves root-level CSV files (test_dataset.csv, network_test_dataset.csv)
into data/samples/ and cleans up the project root.
"""

import os
import shutil

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_DIR = os.path.join(ROOT_DIR, "data", "samples")

CANDIDATES = [
    "test_dataset.csv",
    "network_test_dataset.csv"
]

def migrate():
    os.makedirs(TARGET_DIR, exist_ok=True)
    for fname in CANDIDATES:
        src = os.path.join(ROOT_DIR, fname)
        dst = os.path.join(TARGET_DIR, fname)
        if os.path.exists(src):
            print(f"Moving {fname} -> data/samples/{fname}")
            shutil.move(src, dst)
        else:
            if os.path.exists(dst):
                print(f"Already in target: data/samples/{fname}")
            else:
                print(f"File not found in root: {fname}")

if __name__ == "__main__":
    migrate()
