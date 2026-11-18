"""Canonical matched-class scope filter for cross-dataset transfer.

The product scope is volumetric denial of service and network reconnaissance /
port scanning. External datasets ship incompatible taxonomies (UNSW-NB15 has
``Exploits``, ``Shellcode``, ``Fuzzers``; CIC-IDS-2018 has brute force, web, bot,
and infiltration campaigns). Scoring those rows as "benign" or "attack" answers
a different question than the one the product claims to answer.

This module is the single place that decides which rows are in scope. The rule
is deliberately fail-closed:

* a recognised benign label maps to ``0``;
* a recognised in-scope attack label maps to ``1``;
* everything else is **dropped**, including every ``- Attempted`` row.

Unknown labels are never mapped to ``0``. A missing or unrecognised label is a
reason to exclude a row, not a reason to call it benign.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import pandas as pd

SCOPE_SCHEMA_VERSION = "matched-scope-v1"
MATCHED_LABEL_COLUMN = "__matched_label"
NORMALIZED_LABEL_COLUMN = "__normalized_label"

# CIC-IDS-2017 Kaggle and the DistriNet corrected export use the same canonical
# family names except for ``Portscan`` (lowercase ``s``) in the corrected
# export. The alias is explicit rather than a silent case-insensitive guess.
_CIC2017_BENIGN = frozenset({"BENIGN"})
_CIC2017_POSITIVE = frozenset(
    {
        "DoS Hulk",
        "DoS GoldenEye",
        "DoS slowloris",
        "DoS Slowhttptest",
        "DDoS",
        "PortScan",
    }
)

_CIC2018_BENIGN = frozenset({"Benign"})
_CIC2018_POSITIVE = frozenset(
    {
        "DoS attacks-Hulk",
        "DoS attacks-SlowHTTPTest",
        "DoS attacks-GoldenEye",
        "DoS attacks-Slowloris",
        "DDOS attack-HOIC",
        "DDOS attack-LOIC-UDP",
        "DDoS attacks-LOIC-HTTP",
    }
)

_UNSW_BENIGN = frozenset({"Normal"})
_UNSW_POSITIVE = frozenset({"DoS", "Reconnaissance"})

SCOPE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "cicids2017": {
        "benign": _CIC2017_BENIGN,
        "positive": _CIC2017_POSITIVE,
        "aliases": {},
        "notes": "Kaggle CIC-IDS-2017 export; Label column.",
    },
    "distrinet_cicids2017": {
        "benign": _CIC2017_BENIGN,
        "positive": _CIC2017_POSITIVE,
        "aliases": {"Portscan": "PortScan"},
        "notes": "DistriNet corrected CIC-IDS-2017 export; Label column.",
    },
    "cicids2018": {
        "benign": _CIC2018_BENIGN,
        "positive": _CIC2018_POSITIVE,
        "aliases": {},
        "notes": "CIC-IDS-2018 CICFlowMeter export; Label column.",
    },
    "unsw_nb15": {
        "benign": _UNSW_BENIGN,
        "positive": _UNSW_POSITIVE,
        "aliases": {},
        "notes": "UNSW-NB15 official split; attack_cat column.",
    },
}

_DASHES = ("\u2013", "\u2014", "\u2212")  # en dash, em dash, minus sign
_ATTEMPTED_SUFFIX = "- attempted"


def normalize_label(value: Any) -> str:
    """Strip, collapse whitespace, and normalise dashes in a label.

    The frozen CIC-IDS-2017 exports use U+2013 in web-attack labels and some
    exports carry a UTF-8 BOM in the header or a non-breaking space in a value.
    Normalisation happens before any membership test so a cosmetic difference
    cannot silently move a row into the benign class.

    Results are memoised. A 13-million-row external file otherwise allocates a
    distinct Python string per row, which is several hundred megabytes for a
    handful of distinct labels. Caching returns the same object per label, so
    the per-row label array is only an array of pointers.
    """
    key = value
    if key is None:
        return ""
    try:
        if pd.isna(key):
            return ""
    except (TypeError, ValueError):
        pass
    if not isinstance(key, str):
        key = str(key)
    return _normalize_label_cached(key)


@lru_cache(maxsize=8192)
def _normalize_label_cached(value: str) -> str:
    text = value.lstrip("\ufeff")
    for dash in _DASHES:
        text = text.replace(dash, "-")
    text = text.replace("\u00a0", " ")
    return re.sub(r"\s+", " ", text).strip()


def is_attempted(label: Any) -> bool:
    """Return True for any normalised label ending in ``- Attempted``."""
    return normalize_label(label).lower().endswith(_ATTEMPTED_SUFFIX)


def scope_definition(dataset_name: str) -> dict[str, Any]:
    """Return the frozen scope definition for a dataset name."""
    try:
        return SCOPE_DEFINITIONS[dataset_name]
    except KeyError as exc:
        known = ", ".join(sorted(SCOPE_DEFINITIONS))
        raise KeyError(
            f"unknown dataset {dataset_name!r}; expected one of: {known}"
        ) from exc


def _role_lookup(definition: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    exact: dict[str, str] = {}
    for label in definition["benign"]:
        exact[label] = "benign"
    for label in definition["positive"]:
        exact[label] = "positive"
    for alias, canonical in definition.get("aliases", {}).items():
        role = exact.get(canonical)
        if role is None:
            raise ValueError(
                f"scope alias {alias!r} points at {canonical!r}, which is not in scope"
            )
        exact[alias] = role

    # A case-insensitive fallback catches export spelling drift (for example
    # ``Portscan``) without ever matching an out-of-scope family. Ambiguous
    # keys are rejected instead of guessed.
    folded: dict[str, str] = {}
    ambiguous: set[str] = set()
    for label, role in exact.items():
        key = label.casefold()
        if key in folded and folded[key] != role:
            ambiguous.add(key)
        folded[key] = role
    for key in ambiguous:
        folded.pop(key, None)
    return exact, folded


def _role_for(canonical: str, exact: dict[str, str], folded: dict[str, str]) -> str | None:
    if not canonical:
        return None
    role = exact.get(canonical)
    if role is not None:
        return role
    return folded.get(canonical.casefold())


def filter_matched_scope(
    df: pd.DataFrame,
    dataset_name: str,
    label_col: str = "Label",
) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Filter a frame to the frozen volumetric/scanning scope.

    Parameters
    ----------
    df:
        Source rows. The label column is not modified.
    dataset_name:
        One of :data:`SCOPE_DEFINITIONS`.
    label_col:
        Name of the label column after header normalisation.

    Returns
    -------
    (filtered, audit)
        ``filtered`` keeps only in-scope rows and adds two columns:
        ``__matched_label`` (``0`` benign, ``1`` positive) and
        ``__normalized_label``. ``audit`` records the raw, kept, and dropped
        counts and the exact dropped labels.

    Every ``- Attempted`` row is dropped, even when the underlying family is in
    scope, because the frozen policy excludes unattempted/unconfirmed attack
    traffic from the positive class.
    """
    definition = scope_definition(dataset_name)
    if label_col not in df.columns:
        raise KeyError(f"label column {label_col!r} is not present")

    lookup = _role_lookup(definition)
    canonical = df[label_col].map(normalize_label)
    roles = canonical.map(lambda value: _role_for(value, *lookup))

    benign_mask = roles == "benign"
    positive_mask = roles == "positive"
    attempted_mask = canonical.map(is_attempted)
    missing_mask = canonical == ""
    keep_mask = (benign_mask | positive_mask) & ~attempted_mask

    filtered = df.loc[keep_mask].copy()
    filtered[MATCHED_LABEL_COLUMN] = (
        positive_mask.loc[keep_mask].astype("int8").to_numpy()
    )
    filtered[NORMALIZED_LABEL_COLUMN] = canonical.loc[keep_mask].to_numpy()

    dropped_mask = ~keep_mask
    dropped_labels = canonical.loc[dropped_mask].value_counts(dropna=False)
    audit: dict[str, Any] = {
        "schema_version": SCOPE_SCHEMA_VERSION,
        "dataset": dataset_name,
        "label_col": label_col,
        "raw_rows": int(len(df)),
        "benign_rows": int((benign_mask & ~attempted_mask).sum()),
        "positive_rows": int((positive_mask & ~attempted_mask).sum()),
        "dropped_out_of_scope_rows": int(dropped_mask.sum()),
        "dropped_attempted_rows": int(attempted_mask.sum()),
        "dropped_missing_label_rows": int((missing_mask & dropped_mask).sum()),
        "dropped_label_counts": {
            str(label): int(count) for label, count in dropped_labels.items()
        },
        "benign_labels": sorted(definition["benign"]),
        "positive_labels": sorted(definition["positive"]),
        "policy": (
            "Unrecognised and - Attempted labels are dropped, never mapped to "
            "the benign class."
        ),
    }
    total = (
        audit["benign_rows"]
        + audit["positive_rows"]
        + audit["dropped_out_of_scope_rows"]
    )
    if total != audit["raw_rows"]:
        raise AssertionError(
            f"scope audit does not reconcile: {total} != {audit['raw_rows']}"
        )
    return filtered, audit


def merge_audits(audits: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-chunk or per-file audits into one report object."""
    if not audits:
        raise ValueError("at least one audit is required")
    totals: dict[str, Any] = {
        "schema_version": SCOPE_SCHEMA_VERSION,
        "dataset": audits[0]["dataset"],
        "label_col": audits[0]["label_col"],
        "raw_rows": 0,
        "benign_rows": 0,
        "positive_rows": 0,
        "dropped_out_of_scope_rows": 0,
        "dropped_attempted_rows": 0,
        "dropped_missing_label_rows": 0,
        "dropped_label_counts": {},
        "benign_labels": audits[0]["benign_labels"],
        "positive_labels": audits[0]["positive_labels"],
        "policy": audits[0]["policy"],
        "parts": len(audits),
    }
    for audit in audits:
        for key in (
            "raw_rows",
            "benign_rows",
            "positive_rows",
            "dropped_out_of_scope_rows",
            "dropped_attempted_rows",
            "dropped_missing_label_rows",
        ):
            totals[key] += int(audit[key])
        for label, count in audit["dropped_label_counts"].items():
            totals["dropped_label_counts"][label] = (
                totals["dropped_label_counts"].get(label, 0) + int(count)
            )
    totals["dropped_label_counts"] = dict(
        sorted(totals["dropped_label_counts"].items(), key=lambda item: (-item[1], item[0]))
    )
    total = (
        totals["benign_rows"]
        + totals["positive_rows"]
        + totals["dropped_out_of_scope_rows"]
    )
    if total != totals["raw_rows"]:
        raise AssertionError(
            f"merged scope audit does not reconcile: {total} != {totals['raw_rows']}"
        )
    return totals


__all__ = [
    "MATCHED_LABEL_COLUMN",
    "NORMALIZED_LABEL_COLUMN",
    "SCOPE_DEFINITIONS",
    "SCOPE_SCHEMA_VERSION",
    "filter_matched_scope",
    "is_attempted",
    "merge_audits",
    "normalize_label",
    "scope_definition",
]
