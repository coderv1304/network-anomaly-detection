"""
feature_mapper.py

The live capture tool (pyflowmeter) outputs flow feature names in
snake_case (e.g. 'flow_duration', 'tot_fwd_pkts'), while your model was
trained on the original CIC-IDS-2017 CSV column names, which are
Title Case With Spaces (e.g. 'Flow Duration', 'Total Fwd Packets').

This module bridges the two automatically where it can, and keeps a
log of any feature name it could NOT confidently map, so you can
extend FEATURE_NAME_OVERRIDES below.

HOW TO FIX MISMATCHES
----------------------
1. Run the app + live_capture.py for a minute so some flows come in.
2. Visit http://127.0.0.1:5000/api/unmapped-features in your browser.
3. Run check_features.py to print the exact list of names your model
   expects (from feature_names.pkl).
4. For each unmapped raw name, find its real counterpart in that list
   and add a line to FEATURE_NAME_OVERRIDES below, e.g.:
       "tot_fwd_pkts": "Total Fwd Packets",
5. Restart app.py. Repeat until /api/unmapped-features is empty.
"""

import re

# Known abbreviation expansions used by CICFlowMeter-style tools.
# Extend this dict if you spot more patterns in your unmapped log.
_ABBREVIATIONS = {
    "tot": "total",
    "pkt": "packet",
    "pkts": "packets",
    "len": "length",
    "std": "std",
    "iat": "iat",
    "seg": "segment",
    "byts": "bytes",
    "flg": "flags",
    "cnt": "count",
    "avg": "mean",
}

# Manual overrides for names the automatic normalizer gets wrong.
# Fill this in based on the /api/unmapped-features output — this is
# the file you'll edit most while getting live capture working.
FEATURE_NAME_OVERRIDES = {
    # "raw_name_from_capture_tool": "Exact Column Name In feature_names.pkl",
}

# Populated at runtime; inspect via GET /api/unmapped-features
UNMAPPED_LOG = set()


def _auto_normalize(raw_name: str) -> str:
    """Best-effort snake_case -> 'Title Case With Spaces' conversion."""
    name = raw_name.strip()
    name = re.sub(r"[/_]+", " ", name)
    words = []
    for w in name.split():
        w_lower = w.lower()
        w_expanded = _ABBREVIATIONS.get(w_lower, w_lower)
        words.append(w_expanded.capitalize())
    return " ".join(words)


def normalize_flow_features(raw_flow: dict, expected_features: list) -> dict:
    """Map a raw flow dict's keys onto the model's expected feature
    names wherever possible. Unmatched raw keys are dropped (and
    logged to UNMAPPED_LOG); expected features that never get a value
    are left for the caller to fill with 0."""
    expected_set = set(expected_features)
    result = {}

    for raw_key, value in raw_flow.items():
        if raw_key in expected_set:
            result[raw_key] = value
            continue

        if raw_key in FEATURE_NAME_OVERRIDES:
            result[FEATURE_NAME_OVERRIDES[raw_key]] = value
            continue

        guess = _auto_normalize(raw_key)
        if guess in expected_set:
            result[guess] = value
        else:
            UNMAPPED_LOG.add(raw_key)

    return result