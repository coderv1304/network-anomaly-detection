"""Build the bundled 500-flow sample fixture used by the one-click demo.

The fixture is an extract of the held-out CIC-IDS-2017 Thursday-Friday split,
not synthetic telemetry:

* **350 BENIGN flows** drawn from the Thursday and Friday benign captures and
  spread round-robin over 12 simulated hosts;
* **150 Friday DDoS / PortScan flows** drawn from the Friday afternoon captures
  and assigned to **two** simulated attackers inside a single 300-second window.

Only ``Flow ID``, ``Source IP``, ``Destination IP`` and ``Timestamp`` are
rewritten. Every model feature (including ``Source Port`` and
``Destination Port``) is the value measured by CICFlowMeter in the published
capture. Ground-truth ``Label`` values are retained for reference; the serving
path never reads them.

If the raw captures are absent (a fresh clone: ``data/*.csv`` is gitignored) the
script falls back to a deterministic generator that emits the exact serving
feature schema. The fallback is still scored by the real serving bundle; no
score is ever fabricated.

Both paths are verified the same way: the written fixture is scored with
``models/model_bundle_rf_day_based_seed42.pkl`` through the same decision policy
and ``EvidenceAccumulator`` the application uses, and the build fails unless at
least one flow alert and one host incident open.

Usage:
    python scripts/build_sample_fixture.py
    python scripts/build_sample_fixture.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone

import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# The serving bundle imports its sanitizer from the ``training`` package.
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
DEFAULT_OUTPUT = os.path.join(PROJECT_ROOT, "tests", "fixtures", "sample_flows_500.csv")
BUNDLE_PATH = os.path.join(
    PROJECT_ROOT, "models", "model_bundle_rf_day_based_seed42.pkl"
)
CALIBRATION_PATH = os.path.join(
    PROJECT_ROOT, "models", "calibration_rf_day_based_seed42.json"
)

SEED = 20261118
BENIGN_ROWS = 350
ATTACK_ROWS = 150
BYTE_BUDGET = 250 * 1024

# Two attackers, deliberately not spread thin: each one has to accumulate past
# the incident threshold on its own evidence inside one window.
ATTACKERS = ("172.16.0.11", "172.16.0.12")
ATTACKER_LABELS = ("DDoS", "PortScan")

INTERNAL_HOSTS = tuple(f"192.168.10.{host}" for host in range(21, 31))
EXTERNAL_HOSTS = ("198.51.100.21", "198.51.100.22")
BENIGN_HOSTS = INTERNAL_HOSTS + EXTERNAL_HOSTS  # exactly 12
BENIGN_VICTIM = "192.168.10.50"
EXTERNAL_VICTIM = "198.51.100.50"

# The sample window starts on an epoch boundary divisible by 300 s, so every
# attack flow lands in the same accumulator bucket.
WINDOW_START = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
WINDOW_SECONDS = 300

METADATA_COLUMNS = ("Flow ID", "Source IP", "Destination IP", "Timestamp", "Label")

DATA_FILES = {
    "benign_thursday": (
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "BENIGN",
    ),
    "benign_friday": ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "BENIGN"),
    "DDoS": ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS"),
    "PortScan": (
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "PortScan",
    ),
}

# Read a strided slice of each chunk instead of whole multi-hundred-megabyte
# captures, so the build stays inside a normal laptop's memory.
CHUNK_ROWS = 100_000
CHUNK_STRIDE = 7


def _timestamp(offset_seconds: int) -> str:
    moment = WINDOW_START + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _source_paths(source_dir: str) -> dict[str, str]:
    return {
        key: os.path.join(source_dir, filename)
        for key, (filename, _) in DATA_FILES.items()
    }


def _read_label(path: str, label: str) -> pd.DataFrame | None:
    """Read a strided slice of one labelled capture, or None when absent."""
    if not os.path.isfile(path):
        return None
    chunks = []
    reader = pd.read_csv(
        path,
        low_memory=False,
        encoding="latin-1",
        chunksize=CHUNK_ROWS,
    )
    for chunk in reader:
        chunk.columns = [str(column).strip() for column in chunk.columns]
        if label not in set(chunk["Label"].astype(str).str.strip()):
            continue
        slice_ = chunk[chunk["Label"].astype(str).str.strip() == label]
        if len(slice_):
            chunks.append(slice_.iloc[::CHUNK_STRIDE].copy())
    if not chunks:
        return None
    return pd.concat(chunks, ignore_index=True)


def _deduplicate(frame: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    """Drop repeated feature vectors so the sample is not one repeated flow."""
    return frame.drop_duplicates(subset=feature_columns).reset_index(drop=True)


def _sample(frame: pd.DataFrame, count: int, seed: int) -> pd.DataFrame:
    if len(frame) < count:
        raise SystemExit(f"Source has {len(frame)} unique rows; {count} requested.")
    rng = random.Random(seed)
    positions = sorted(rng.sample(range(len(frame)), count))
    return frame.iloc[positions].reset_index(drop=True)


def _existing_sources(source_dir: str) -> dict[str, str]:
    paths = _source_paths(source_dir)
    missing = [key for key, path in paths.items() if not os.path.isfile(path)]
    return {} if missing else paths


# ---------------------------------------------------------------------------
# Real capture path
# ---------------------------------------------------------------------------
def _build_from_captures(source_dir: str) -> pd.DataFrame:
    paths = _existing_sources(source_dir)
    benign_parts = []
    for key, offset in (("benign_thursday", 0), ("benign_friday", 1)):
        frame = _read_label(paths[key], DATA_FILES[key][1])
        if frame is None or frame.empty:
            raise SystemExit(f"No BENIGN rows in {paths[key]}")
        benign_parts.append((frame, offset))

    feature_columns = [c for c in benign_parts[0][0].columns if c not in METADATA_COLUMNS]
    if len(feature_columns) != 80:
        raise SystemExit(
            f"Expected the 80-feature CIC schema, found {len(feature_columns)} features."
        )

    benign_frames = []
    for pool, _ in benign_parts:
        benign_frames.append(_deduplicate(pool, feature_columns))
    halves = (BENIGN_ROWS + 1) // 2, BENIGN_ROWS // 2
    benign = pd.concat(
        [
            _sample(frame, count, SEED + index)
            for index, (frame, count) in enumerate(zip(benign_frames, halves))
        ],
        ignore_index=True,
    )

    attacks = []
    per_attacker = ATTACK_ROWS // len(ATTACKERS)
    for index, (attacker, label) in enumerate(zip(ATTACKERS, ATTACKER_LABELS)):
        frame = _read_label(paths[label], label)
        if frame is None:
            raise SystemExit(f"No {label} rows in {paths[label]}")
        picked = _sample(_deduplicate(frame, feature_columns), per_attacker, SEED + 10 + index)
        picked["Source IP"] = attacker
        picked["Destination IP"] = BENIGN_VICTIM if index == 0 else EXTERNAL_VICTIM
        picked["Label"] = label
        base_offset = 6 + index * 4
        step = max(1, (WINDOW_SECONDS - 20) // max(1, per_attacker - 1))
        picked["Timestamp"] = [
            _timestamp(min(WINDOW_SECONDS - 5, base_offset + position * step))
            for position in range(per_attacker)
        ]
        attacks.append(picked)

    # Round-robin, one flow every ~0.85 s per host: no benign host ever builds a
    # dense burst, so an incident there would have to come from false positives.
    benign["Source IP"] = [BENIGN_HOSTS[i % len(BENIGN_HOSTS)] for i in range(len(benign))]
    benign["Destination IP"] = [BENIGN_VICTIM if i % 3 else EXTERNAL_VICTIM for i in range(len(benign))]
    benign["Timestamp"] = [
        _timestamp((i * (WINDOW_SECONDS - 5)) // max(1, len(benign) - 1))
        for i in range(len(benign))
    ]

    combined = pd.concat([benign, *attacks], ignore_index=True)
    columns = [c for c in benign.columns if c in combined.columns]
    return combined[columns]


# ---------------------------------------------------------------------------
# Deterministic fallback: exact serving feature schema, plausible traffic
# ---------------------------------------------------------------------------
def _serve_features() -> list[str]:
    import joblib

    if not os.path.isfile(BUNDLE_PATH):
        raise SystemExit(f"Missing serving bundle: {BUNDLE_PATH}")
    return list(joblib.load(BUNDLE_PATH)["feature_names"])


def _template(features: list[str], values: dict) -> dict:
    row = {name: 0 for name in features}
    row.update(values)
    return row


def _jitter(base: dict, rng: random.Random, spread: float = 0.15) -> dict:
    row = {}
    for name, value in base.items():
        if isinstance(value, (int, float)) and value not in (0, 1):
            factor = 1.0 + rng.uniform(-spread, spread)
            row[name] = round(float(value) * factor, 6)
        else:
            row[name] = value
    return row


def _benign_templates(features: list[str]) -> list[dict]:
    shared = {
        "Fwd Header Length": 160,
        "Bwd Header Length": 180,
        "SYN Flag Count": 1,
        "ACK Flag Count": 1,
        "PSH Flag Count": 1,
        "min_seg_size_forward": 20,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
    }
    https = _template(
        features,
        {
            **shared,
            "Protocol": 6,
            "Destination Port": 443,
            "Flow Duration": 2_000_000,
            "Total Fwd Packets": 8,
            "Total Backward Packets": 9,
            "Total Length of Fwd Packets": 900,
            "Total Length of Bwd Packets": 4000,
            "Fwd Packet Length Max": 500,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 112,
            "Fwd Packet Length Std": 150,
            "Bwd Packet Length Max": 1400,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 444,
            "Bwd Packet Length Std": 500,
            "Flow Bytes/s": 2450,
            "Flow Packets/s": 8.5,
            "Flow IAT Mean": 117000,
            "Flow IAT Std": 200000,
            "Flow IAT Max": 900000,
            "Flow IAT Min": 20,
            "Fwd IAT Total": 2_000_000,
            "Fwd IAT Mean": 250000,
            "Fwd IAT Std": 300000,
            "Fwd IAT Max": 900000,
            "Fwd IAT Min": 20,
            "Bwd IAT Total": 1_900_000,
            "Bwd IAT Mean": 210000,
            "Bwd IAT Std": 280000,
            "Bwd IAT Max": 880000,
            "Bwd IAT Min": 40,
            "Min Packet Length": 0,
            "Max Packet Length": 1400,
            "Packet Length Mean": 288,
            "Packet Length Std": 430,
            "Packet Length Variance": 184900,
            "Down/Up Ratio": 1,
            "Average Packet Size": 288,
            "Avg Fwd Segment Size": 112,
            "Avg Bwd Segment Size": 444,
            "Subflow Fwd Packets": 8,
            "Subflow Fwd Bytes": 900,
            "Subflow Bwd Packets": 9,
            "Subflow Bwd Bytes": 4000,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 229,
            "act_data_pkt_fwd": 6,
            "Active Mean": 1000,
            "Active Std": 100,
            "Active Max": 2000,
            "Active Min": 100,
            "Idle Mean": 600000,
            "Idle Std": 20000,
            "Idle Max": 900000,
            "Idle Min": 100,
        },
    )
    http = _template(
        features,
        {
            **shared,
            "Protocol": 6,
            "Destination Port": 80,
            "Flow Duration": 350000,
            "Total Fwd Packets": 12,
            "Total Backward Packets": 14,
            "Total Length of Fwd Packets": 5400,
            "Total Length of Bwd Packets": 22000,
            "Fwd Packet Length Max": 1400,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 450,
            "Fwd Packet Length Std": 520,
            "Bwd Packet Length Max": 1400,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 1571,
            "Bwd Packet Length Std": 430,
            "Flow Bytes/s": 78000,
            "Flow Packets/s": 74,
            "Flow IAT Mean": 13000,
            "Flow IAT Std": 21000,
            "Flow IAT Max": 90000,
            "Flow IAT Min": 12,
            "Fwd IAT Total": 350000,
            "Fwd IAT Mean": 29000,
            "Fwd IAT Std": 31000,
            "Fwd IAT Max": 90000,
            "Fwd IAT Min": 15,
            "Bwd IAT Total": 340000,
            "Bwd IAT Mean": 24000,
            "Bwd IAT Std": 26000,
            "Bwd IAT Max": 88000,
            "Bwd IAT Min": 18,
            "Min Packet Length": 0,
            "Max Packet Length": 1400,
            "Packet Length Mean": 1015,
            "Packet Length Std": 620,
            "Packet Length Variance": 384400,
            "Down/Up Ratio": 1,
            "Average Packet Size": 1015,
            "Avg Fwd Segment Size": 450,
            "Avg Bwd Segment Size": 1571,
            "Subflow Fwd Packets": 12,
            "Subflow Fwd Bytes": 5400,
            "Subflow Bwd Packets": 14,
            "Subflow Bwd Bytes": 22000,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 235,
            "act_data_pkt_fwd": 9,
            "Active Mean": 800,
            "Active Std": 90,
            "Active Max": 1500,
            "Active Min": 80,
            "Idle Mean": 70000,
            "Idle Std": 9000,
            "Idle Max": 120000,
            "Idle Min": 60,
        },
    )
    ssh = _template(
        features,
        {
            **shared,
            "Protocol": 6,
            "Destination Port": 22,
            "Flow Duration": 45_000_000,
            "Total Fwd Packets": 26,
            "Total Backward Packets": 24,
            "Total Length of Fwd Packets": 4200,
            "Total Length of Bwd Packets": 6100,
            "Fwd Packet Length Max": 320,
            "Fwd Packet Length Min": 0,
            "Fwd Packet Length Mean": 161,
            "Fwd Packet Length Std": 96,
            "Bwd Packet Length Max": 380,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 254,
            "Bwd Packet Length Std": 110,
            "Flow Bytes/s": 228,
            "Flow Packets/s": 1.11,
            "Flow IAT Mean": 900000,
            "Flow IAT Std": 1400000,
            "Flow IAT Max": 9000000,
            "Flow IAT Min": 30,
            "Fwd IAT Total": 45_000_000,
            "Fwd IAT Mean": 1800000,
            "Fwd IAT Std": 2600000,
            "Fwd IAT Max": 9000000,
            "Fwd IAT Min": 30,
            "Bwd IAT Total": 44_000_000,
            "Bwd IAT Mean": 1900000,
            "Bwd IAT Std": 2500000,
            "Bwd IAT Max": 8800000,
            "Bwd IAT Min": 40,
            "Min Packet Length": 0,
            "Max Packet Length": 380,
            "Packet Length Mean": 206,
            "Packet Length Std": 105,
            "Packet Length Variance": 11025,
            "Down/Up Ratio": 1,
            "Average Packet Size": 206,
            "Avg Fwd Segment Size": 161,
            "Avg Bwd Segment Size": 254,
            "Subflow Fwd Packets": 26,
            "Subflow Fwd Bytes": 4200,
            "Subflow Bwd Packets": 24,
            "Subflow Bwd Bytes": 6100,
            "Init_Win_bytes_forward": 8192,
            "Init_Win_bytes_backward": 245,
            "act_data_pkt_fwd": 18,
            "Active Mean": 4000,
            "Active Std": 600,
            "Active Max": 9000,
            "Active Min": 200,
            "Idle Mean": 4_000_000,
            "Idle Std": 500000,
            "Idle Max": 9_000_000,
            "Idle Min": 1000,
        },
    )
    dns = _template(
        features,
        {
            **shared,
            "Destination Port": 53,
            "Protocol": 17,
            "Flow Duration": 9000,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Total Length of Fwd Packets": 64,
            "Total Length of Bwd Packets": 148,
            "Fwd Packet Length Max": 64,
            "Fwd Packet Length Min": 64,
            "Fwd Packet Length Mean": 64,
            "Fwd Packet Length Std": 0,
            "Bwd Packet Length Max": 148,
            "Bwd Packet Length Min": 148,
            "Bwd Packet Length Mean": 148,
            "Bwd Packet Length Std": 0,
            "Flow Bytes/s": 23555,
            "Flow Packets/s": 222,
            "Flow IAT Mean": 0,
            "Flow IAT Std": 0,
            "Flow IAT Max": 0,
            "Flow IAT Min": 0,
            "Fwd IAT Total": 0,
            "Fwd IAT Mean": 0,
            "Fwd IAT Std": 0,
            "Fwd IAT Max": 0,
            "Fwd IAT Min": 0,
            "Bwd IAT Total": 0,
            "Bwd IAT Mean": 0,
            "Bwd IAT Std": 0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "SYN Flag Count": 0,
            "ACK Flag Count": 0,
            "PSH Flag Count": 0,
            "Fwd Header Length": 40,
            "Bwd Header Length": 40,
            "Min Packet Length": 64,
            "Max Packet Length": 148,
            "Packet Length Mean": 106,
            "Packet Length Std": 42,
            "Packet Length Variance": 1764,
            "Down/Up Ratio": 1,
            "Average Packet Size": 106,
            "Avg Fwd Segment Size": 64,
            "Avg Bwd Segment Size": 148,
            "Subflow Fwd Packets": 1,
            "Subflow Fwd Bytes": 64,
            "Subflow Bwd Packets": 1,
            "Subflow Bwd Bytes": 148,
            "Init_Win_bytes_forward": 0,
            "Init_Win_bytes_backward": 0,
            "act_data_pkt_fwd": 1,
            "Idle Mean": 0,
            "Idle Max": 0,
            "Idle Min": 0,
        },
    )
    return [https, http, ssh, dns]


def _attack_templates(features: list[str]) -> dict[str, dict]:
    syn_flood = _template(
        features,
        {
            "Destination Port": 80,
            "Protocol": 6,
            "Flow Duration": 120,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 0,
            "Fwd Header Length": 40,
            "Bwd Header Length": 0,
            "Flow Packets/s": 16666,
            "Fwd Packets/s": 16666,
            "Flow IAT Mean": 60,
            "Flow IAT Std": 0,
            "Flow IAT Max": 120,
            "Flow IAT Min": 60,
            "Fwd IAT Total": 120,
            "Fwd IAT Mean": 60,
            "Fwd IAT Max": 120,
            "Fwd IAT Min": 60,
            "SYN Flag Count": 1,
            "Init_Win_bytes_forward": 1024,
            "Subflow Fwd Packets": 2,
            "act_data_pkt_fwd": 1,
            "min_seg_size_forward": 20,
        },
    )
    port_scan = _template(
        features,
        {
            "Destination Port": 22,
            "Protocol": 6,
            "Flow Duration": 3,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Fwd Header Length": 40,
            "Bwd Header Length": 0,
            "Flow Packets/s": 333333,
            "Fwd Packets/s": 333333,
            "Flow IAT Mean": 0,
            "Flow IAT Max": 0,
            "SYN Flag Count": 1,
            "Init_Win_bytes_forward": 8192,
            "Subflow Fwd Packets": 1,
            "act_data_pkt_fwd": 1,
            "min_seg_size_forward": 20,
        },
    )
    return {"DDoS": syn_flood, "PortScan": port_scan}


def _build_fallback() -> pd.DataFrame:
    features = _serve_features()
    rng = random.Random(SEED)
    benign_templates = _benign_templates(features)
    attack_templates = _attack_templates(features)

    rows = []
    for index in range(BENIGN_ROWS):
        template = benign_templates[index % len(benign_templates)]
        row = _jitter(template, rng)
        row["Source Port"] = 49152 + (index % 16000)
        row["Source IP"] = BENIGN_HOSTS[index % len(BENIGN_HOSTS)]
        row["Destination IP"] = BENIGN_VICTIM if index % 3 else EXTERNAL_VICTIM
        row["Timestamp"] = _timestamp((index * (WINDOW_SECONDS - 5)) // BENIGN_ROWS)
        row["Label"] = "BENIGN"
        rows.append(row)

    per_attacker = ATTACK_ROWS // len(ATTACKERS)
    attacks = []
    for index, (attacker, label) in enumerate(zip(ATTACKERS, ATTACKER_LABELS)):
        step = max(1, (WINDOW_SECONDS - 20) // max(1, per_attacker - 1))
        for position in range(per_attacker):
            row = _jitter(attack_templates[label], rng, spread=0.08)
            row["Source Port"] = 32768 + (position % 20000)
            row["Source IP"] = attacker
            row["Destination IP"] = BENIGN_VICTIM if index == 0 else EXTERNAL_VICTIM
            row["Timestamp"] = _timestamp(
                min(WINDOW_SECONDS - 5, 6 + index * 4 + position * step)
            )
            row["Label"] = label
            attacks.append(row)

    frame = pd.DataFrame(rows + attacks)
    frame.insert(0, "Flow ID", [f"sample-{i:04d}" for i in range(len(frame))])
    ordered = ["Flow ID", "Source IP", "Destination IP", "Timestamp", *features, "Label"]
    return frame[ordered]


# ---------------------------------------------------------------------------
# Write and verify
# ---------------------------------------------------------------------------
def _format(value: str) -> str:
    """Render a numeric cell compactly without losing meaningful precision."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return value
    if not math.isfinite(number):
        return "0"
    if number == int(number) and abs(number) < 1e15:
        return str(int(number))
    return f"{number:.6g}"


def write_fixture(frame: pd.DataFrame, output: str) -> None:
    printable = frame.copy()
    for column in printable.columns:
        if column in METADATA_COLUMNS or column in {"Source Port", "Destination Port", "Protocol"}:
            continue
        printable[column] = printable[column].map(_format)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    printable.to_csv(output, index=False, lineterminator="\n")


def _epoch(value) -> float:
    moment = pd.to_datetime(str(value), utc=True, errors="coerce")
    if pd.isna(moment):
        return float(WINDOW_START.timestamp())
    return float(moment.timestamp())


def score_and_accumulate(path: str) -> dict:
    """Score the fixture with the real serving bundle and the real accumulator.

    Nothing here mocks a score: the bundle's own pipeline produces the attack
    score, the recorded threshold decides the per-flow alert, the shipped
    isotonic artifact calibrates it, and ``EvidenceAccumulator`` in its serving
    ``calibrated`` mode decides the host/window incident.
    """
    import joblib

    from evidence_accumulator import EvidenceAccumulator, Observation, load_calibrator

    bundle = joblib.load(BUNDLE_PATH)
    pipeline = bundle["pipeline"]
    encoder = bundle["label_encoder"]
    feature_names = list(bundle["feature_names"])
    classifier = pipeline.named_steps.get("classifier")
    benign_index = list(classifier.classes_).index(encoder.transform(["BENIGN"])[0])
    threshold = float(bundle["attack_threshold"])

    calibrator = None
    calibration_status = "uncalibrated"
    if os.path.isfile(CALIBRATION_PATH):
        candidate, metadata = load_calibrator(CALIBRATION_PATH)
        bundle_hash = hashlib.sha256(open(BUNDLE_PATH, "rb").read()).hexdigest()
        if metadata.get("artifact_sha256") == bundle_hash:
            calibrator = candidate
            calibration_status = str(metadata.get("calibration_version") or "calibrated")
        else:
            calibration_status = "calibration_hash_mismatch"

    frame = pd.read_csv(path, low_memory=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    matrix = frame.reindex(columns=feature_names).apply(pd.to_numeric, errors="coerce")
    probabilities = pipeline.predict_proba(matrix)
    raw_scores = 1.0 - probabilities[:, benign_index]
    flagged = raw_scores >= threshold

    accumulator = EvidenceAccumulator(scoring_mode="calibrated")
    for position, raw in enumerate(raw_scores):
        calibrated = calibrator(float(raw)) if calibrator is not None else float(raw)
        row = frame.iloc[position]
        accumulator.observe(
            Observation(
                source_ip=str(row["Source IP"]),
                timestamp=_epoch(row["Timestamp"]),
                supervised_probability=float(calibrated),
                supervised_calibration=calibration_status,
                destination_ip=str(row["Destination IP"]),
                destination_port=int(float(row["Destination Port"])),
            )
        )
    snapshot = accumulator.snapshot(open_only=False, limit=1000)
    incidents = [item for item in snapshot["incidents"] if item["incident_open"]]
    attack_sources = set(frame.loc[flagged, "Source IP"].astype(str))
    attack_incidents = [
        item for item in incidents if item["source_ip"] in attack_sources
    ]
    return {
        "flow_alerts": int(flagged.sum()),
        "alert_sources": sorted(attack_sources),
        "incidents": len(incidents),
        "attack_incidents": len(attack_incidents),
        "incident_details": [
            {
                "source_ip": item["source_ip"],
                "window_start": item["window_start"],
                "risk_points": item["risk_points"],
                "flow_count": item["flow_count"],
                "active_signals": item["active_signals"],
            }
            for item in incidents
        ],
        "threshold": threshold,
        "calibration_status": calibration_status,
    }


def summarize(path: str) -> dict:
    frame = pd.read_csv(path, low_memory=False)
    frame.columns = [str(column).strip() for column in frame.columns]
    labels = frame["Label"].astype(str).str.strip().value_counts().to_dict()
    timestamps = pd.to_datetime(frame["Timestamp"], utc=True)
    attack = frame["Label"].astype(str).str.strip() != "BENIGN"
    return {
        "path": os.path.relpath(path, PROJECT_ROOT).replace("\\", "/"),
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "labels": labels,
        "bytes": os.path.getsize(path),
        "sha256": hashlib.sha256(open(path, "rb").read()).hexdigest(),
        "distinct_sources": int(frame["Source IP"].nunique()),
        "benign_sources": int(frame.loc[~attack, "Source IP"].nunique()),
        "attack_sources": int(frame.loc[attack, "Source IP"].nunique()),
        "attack_window_seconds": int(
            (timestamps[attack].max() - timestamps[attack].min()).total_seconds()
        ),
        "timestamps": [str(timestamps.min()), str(timestamps.max())],
        "non_finite_features": int(
            (~frame.select_dtypes(include="number").apply(
                lambda column: column.map(lambda value: math.isfinite(value))
            )).sum().sum()
        ),
    }


def _report(path: str) -> int:
    report = summarize(path)
    print(report)
    verification = score_and_accumulate(path)
    print(verification)
    problems = []
    if report["bytes"] >= BYTE_BUDGET:
        problems.append(f"fixture is {report['bytes']} bytes, budget is {BYTE_BUDGET}")
    if report["rows"] != 500:
        problems.append(f"expected 500 rows, found {report['rows']}")
    if verification["flow_alerts"] < 1:
        problems.append("no per-flow alert was emitted by the serving bundle")
    if verification["incidents"] < 1:
        problems.append("no host/window incident opened")
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--source-dir",
        default=os.path.join(PROJECT_ROOT, "data"),
        help="Directory holding the CIC-IDS-2017 daily CSVs",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed fixture instead of rebuilding it",
    )
    args = parser.parse_args(argv)

    if args.check:
        if not os.path.isfile(args.output):
            print(f"Missing fixture: {args.output}", file=sys.stderr)
            return 1
        return _report(args.output)

    if _existing_sources(args.source_dir):
        frame = _build_from_captures(args.source_dir)
        origin = "cic-ids-2017 thursday-friday captures"
    else:
        frame = _build_fallback()
        origin = "deterministic schema-exact fallback"
    write_fixture(frame, args.output)
    print(f"source: {origin}")
    return _report(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
