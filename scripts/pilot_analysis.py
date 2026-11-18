#!/usr/bin/env python
"""S7 design-partner pilot analysis harness.

This script computes the predeclared S7 metrics from exported pilot logs. It
does not create a pilot, does not simulate human evidence, and refuses to call
synthetic input real evidence.

Expected input directory (all CSV unless noted):

``provenance.json``
    site, pilot_lead, start_date, end_date, model_version, artifact_sha256,
    feature_schema, threshold_policy, calibration_version, model_changes,
    paused, approval_date, approver.

``onboarding.csv``
    participant_id, role, start_utc, end_utc, completed.

``daily.csv``
    date, eligible_flows, alerts_queued, alerts_reviewed,
    unreviewed_due_to_cap, cap_hit, queue_latency_p50_s, queue_latency_p95_s.

``reviews.csv``
    alert_id, analyst_id, date, opened_utc, closed_utc, disposition,
    confidence, external_lookup, escalated, model_family.

``ground_truth.csv`` (optional)
    alert_id, confirmed_attack.

``missed_attacks.csv`` (optional)
    missed_id, discovered_via, confirmed_attack, estimated_impact.

``support.csv`` (optional)
    ticket_id, opened_utc, first_response_utc, closed_utc, severity, category.

``costs.json`` (optional)
    analyst_hourly_cost, missed_attack_cost, currency. Use null when the site
    did not supply a figure. Never invent one.

``criteria.json`` (optional override of the predeclared gates).

Run:
    python scripts/pilot_analysis.py --input-dir pilot_data --output docs/s7_pilot_analysis.json
    python scripts/pilot_analysis.py --self-test --output docs/s7_pilot_analysis_selftest.json
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

DISPOSITIONS = {"true_attack", "benign", "inconclusive", "duplicate", "out_of_scope"}
FP_DISPOSITIONS = {"benign", "inconclusive", "duplicate", "out_of_scope"}

DEFAULT_CRITERIA = {
    "min_reviewed_alerts": 300,
    "onboarding_median_minutes_max": 60.0,
    "onboarding_completion_min": 0.90,
    "alerts_per_10k_p95_max": 100.0,
    "review_completion_min": 0.95,
    "median_review_seconds_max": 180.0,
    "p95_review_seconds_max": 600.0,
    "yield_min": 0.50,
    "yield_wilson_lower_min": 0.40,
    "fp_minutes_share_max": 0.50,
    "analyst_minutes_per_confirmed_attack_max": 6.0,
    "support_tickets_per_analyst_week_max": 2.0,
    "support_first_response_median_hours_max": 4.0,
    "p1_unresolved_over_24h_max": 0,
}


def read_csv(directory: Path, name: str) -> pd.DataFrame | None:
    path = directory / name
    if not path.is_file():
        return None
    return pd.read_csv(path)


def read_json(directory: Path, name: str, default: dict | None = None) -> dict:
    path = directory / name
    if not path.is_file():
        return default or {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def wilson(successes: int, total: int, z: float = 1.96) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * np.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [max(0.0, float(center - margin)), min(1.0, float(center + margin))]


def to_datetime(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    for column in columns:
        if column in frame.columns:
            frame[column] = pd.to_datetime(frame[column], utc=True, errors="coerce")
    return frame


def duration_seconds(frame: pd.DataFrame, start: str, end: str) -> pd.Series:
    return (frame[end] - frame[start]).dt.total_seconds()


def check(check_id: str, requirement: str, observed: Any, passed: bool, detail: str = "") -> dict:
    return {
        "id": check_id,
        "requirement": requirement,
        "observed": observed,
        "pass": bool(passed),
        "detail": detail,
    }


def analyze(directory: Path, synthetic: bool = False) -> dict[str, Any]:
    criteria = {**DEFAULT_CRITERIA, **read_json(directory, "criteria.json")}
    provenance = read_json(directory, "provenance.json")
    costs = read_json(directory, "costs.json")

    onboarding = read_csv(directory, "onboarding.csv")
    daily = read_csv(directory, "daily.csv")
    reviews = read_csv(directory, "reviews.csv")
    ground_truth = read_csv(directory, "ground_truth.csv")
    missed = read_csv(directory, "missed_attacks.csv")
    support = read_csv(directory, "support.csv")

    if daily is None or reviews is None:
        raise SystemExit("daily.csv and reviews.csv are required")

    daily = to_datetime(daily.copy(), ["date"])
    reviews = to_datetime(reviews.copy(), ["date", "opened_utc", "closed_utc"])
    if onboarding is not None:
        onboarding = to_datetime(onboarding.copy(), ["start_utc", "end_utc"])
    if support is not None:
        support = to_datetime(support.copy(), ["opened_utc", "first_response_utc", "closed_utc"])

    data_issues: list[str] = []
    required_review_columns = [
        "alert_id",
        "analyst_id",
        "date",
        "opened_utc",
        "closed_utc",
        "disposition",
    ]
    missing_review = [column for column in required_review_columns if column not in reviews.columns]
    if missing_review:
        raise SystemExit("reviews.csv missing required columns: " + ", ".join(missing_review))
    required_daily_columns = ["date", "alerts_queued", "eligible_flows"]
    missing_daily = [column for column in required_daily_columns if column not in daily.columns]
    if missing_daily:
        raise SystemExit("daily.csv missing required columns: " + ", ".join(missing_daily))
    if reviews["alert_id"].duplicated().any():
        data_issues.append("duplicate alert_id in reviews.csv")
    reviews["review_seconds"] = duration_seconds(reviews, "opened_utc", "closed_utc")
    if (reviews["review_seconds"] < 0).any():
        data_issues.append("negative review duration")
    if not reviews["disposition"].isin(DISPOSITIONS).all():
        data_issues.append("unknown disposition value")

    reviewed = int(len(reviews))
    queued = int(daily["alerts_queued"].sum()) if "alerts_queued" in daily else reviewed
    review_completion = reviewed / queued if queued else None
    eligible_flows = int(daily["eligible_flows"].sum()) if "eligible_flows" in daily else None
    daily_alerts_per_10k = (
        daily["alerts_queued"] / daily["eligible_flows"].replace(0, np.nan) * 10_000.0
        if "alerts_queued" in daily and "eligible_flows" in daily
        else pd.Series(dtype=float)
    )
    alerts_per_10k = (
        queued / eligible_flows * 10_000.0 if eligible_flows else None
    )
    alerts_per_10k_p95 = (
        float(daily_alerts_per_10k.quantile(0.95)) if len(daily_alerts_per_10k.dropna()) else None
    )

    disposition_counts = reviews["disposition"].value_counts().to_dict()
    true_attacks = int((reviews["disposition"] == "true_attack").sum())
    yield_value = true_attacks / reviewed if reviewed else None
    yield_interval = wilson(true_attacks, reviewed)

    total_review_minutes = float(reviews["review_seconds"].sum() / 60.0)
    fp_minutes = float(
        reviews.loc[reviews["disposition"].isin(FP_DISPOSITIONS), "review_seconds"].sum() / 60.0
    )
    fp_minutes_share = fp_minutes / total_review_minutes if total_review_minutes else None

    confirmed_attacks = None
    if ground_truth is not None and "confirmed_attack" in ground_truth:
        merged = reviews.merge(ground_truth[["alert_id", "confirmed_attack"]], on="alert_id", how="left")
        confirmed_attacks = int((merged["confirmed_attack"] == 1).sum())
    analyst_minutes_per_confirmed_attack = (
        total_review_minutes / confirmed_attacks if confirmed_attacks else None
    )

    onboarding_metrics = None
    if onboarding is not None and "start_utc" in onboarding and "end_utc" in onboarding:
        onboarding["onboarding_minutes"] = duration_seconds(onboarding, "start_utc", "end_utc") / 60.0
        onboarding_metrics = {
            "participants": int(len(onboarding)),
            "completion_rate": float(onboarding["completed"].mean()) if "completed" in onboarding else None,
            "median_minutes": float(onboarding["onboarding_minutes"].median()),
            "p95_minutes": float(onboarding["onboarding_minutes"].quantile(0.95)),
        }

    n_analysts = int(reviews["analyst_id"].nunique())
    day_count = int(reviews["date"].dt.date.nunique()) if "date" in reviews else 0
    weeks = max(day_count / 7.0, 1 / 7.0)
    support_metrics = None
    if support is not None:
        support["first_response_hours"] = (
            (support["first_response_utc"] - support["opened_utc"]).dt.total_seconds() / 3600.0
        )
        end = pd.to_datetime(provenance.get("end_date"), utc=True) if provenance.get("end_date") else None
        closed = support["closed_utc"].fillna(end) if end is not None else support["closed_utc"]
        support["open_hours"] = (closed - support["opened_utc"]).dt.total_seconds() / 3600.0
        p1 = support[support["severity"].astype(str).str.upper() == "P1"]
        support_metrics = {
            "tickets": int(len(support)),
            "tickets_per_analyst_week": float(len(support) / (n_analysts * weeks)) if n_analysts else None,
            "median_first_response_hours": float(support["first_response_hours"].median()),
            "p95_first_response_hours": float(support["first_response_hours"].quantile(0.95)),
            "median_resolution_hours": float(support["open_hours"].median()),
            "p1_tickets": int(len(p1)),
            "p1_unresolved_over_24h": int((p1["open_hours"] > 24).sum()),
        }

    missed_count = None
    if missed is not None:
        missed_count = int((missed.get("confirmed_attack", pd.Series([1] * len(missed))) == 1).sum())

    cost_metrics = None
    analyst_hourly = costs.get("analyst_hourly_cost")
    missed_cost = costs.get("missed_attack_cost")
    if analyst_hourly is not None:
        analyst_cost = total_review_minutes / 60.0 * float(analyst_hourly)
        cost_metrics = {
            "currency": costs.get("currency"),
            "analyst_hourly_cost": analyst_hourly,
            "analyst_cost_for_reviewed_alerts": round(analyst_cost, 2),
        }
        if missed_cost is not None and missed_count is not None:
            cost_metrics["missed_attack_cost"] = missed_cost
            cost_metrics["estimated_missed_attack_cost"] = round(missed_count * float(missed_cost), 2)
            cost_metrics["net_pilot_cost"] = round(
                analyst_cost + missed_count * float(missed_cost), 2
            )

    model_changes = provenance.get("model_changes")
    checks = [
        check(
            "data_integrity",
            "Required exports are present, alert IDs are unique, durations are non-negative, dispositions are valid.",
            data_issues or "ok",
            not data_issues,
        ),
        check(
            "sample_size",
            f"At least {criteria['min_reviewed_alerts']} reviewed alerts.",
            reviewed,
            reviewed >= criteria["min_reviewed_alerts"],
        ),
        check(
            "onboarding",
            f"Median onboarding <= {criteria['onboarding_median_minutes_max']} min and completion >= "
            f"{criteria['onboarding_completion_min']:.0%}.",
            onboarding_metrics,
            bool(
                onboarding_metrics
                and onboarding_metrics["median_minutes"] <= criteria["onboarding_median_minutes_max"]
                and (onboarding_metrics["completion_rate"] or 0) >= criteria["onboarding_completion_min"]
            ),
        ),
        check(
            "alert_budget",
            f"Daily alert rate p95 <= {criteria['alerts_per_10k_p95_max']}/10k flows and review completion >= "
            f"{criteria['review_completion_min']:.0%}.",
            {"alerts_per_10k": alerts_per_10k, "p95": alerts_per_10k_p95, "completion": review_completion},
            bool(
                alerts_per_10k_p95 is not None
                and alerts_per_10k_p95 <= criteria["alerts_per_10k_p95_max"]
                and (review_completion or 0) >= criteria["review_completion_min"]
            ),
        ),
        check(
            "analyst_time",
            f"Median review <= {criteria['median_review_seconds_max']}s and p95 <= "
            f"{criteria['p95_review_seconds_max']}s.",
            {
                "median_s": float(reviews["review_seconds"].median()),
                "p95_s": float(reviews["review_seconds"].quantile(0.95)),
            },
            bool(
                reviews["review_seconds"].median() <= criteria["median_review_seconds_max"]
                and reviews["review_seconds"].quantile(0.95) <= criteria["p95_review_seconds_max"]
            ),
        ),
        check(
            "yield",
            f"True-positive yield >= {criteria['yield_min']:.0%} and Wilson lower bound >= "
            f"{criteria['yield_wilson_lower_min']:.0%}.",
            {"yield": yield_value, "wilson_95": yield_interval},
            bool(
                yield_value is not None
                and yield_interval is not None
                and yield_value >= criteria["yield_min"]
                and yield_interval[0] >= criteria["yield_wilson_lower_min"]
            ),
        ),
        check(
            "false_positive_cost",
            f"FP review time <= {criteria['fp_minutes_share_max']:.0%} of review time and <= "
            f"{criteria['analyst_minutes_per_confirmed_attack_max']} analyst minutes per confirmed attack.",
            {
                "fp_minutes_share": fp_minutes_share,
                "analyst_minutes_per_confirmed_attack": analyst_minutes_per_confirmed_attack,
            },
            bool(
                fp_minutes_share is not None
                and fp_minutes_share <= criteria["fp_minutes_share_max"]
                and (
                    analyst_minutes_per_confirmed_attack is None
                    or analyst_minutes_per_confirmed_attack
                    <= criteria["analyst_minutes_per_confirmed_attack_max"]
                )
            ),
        ),
        check(
            "support_load",
            f"Support tickets <= {criteria['support_tickets_per_analyst_week_max']}/analyst-week, median first "
            f"response <= {criteria['support_first_response_median_hours_max']}h, P1 open >24h <= "
            f"{criteria['p1_unresolved_over_24h_max']}.",
            support_metrics,
            bool(
                support_metrics
                and support_metrics["tickets_per_analyst_week"]
                <= criteria["support_tickets_per_analyst_week_max"]
                and support_metrics["median_first_response_hours"]
                <= criteria["support_first_response_median_hours_max"]
                and support_metrics["p1_unresolved_over_24h"]
                <= criteria["p1_unresolved_over_24h_max"]
            ),
        ),
        check(
            "model_stability",
            "No model or threshold change during the pilot.",
            model_changes,
            model_changes in (None, 0, "0", "none", "None", "no", "No"),
        ),
        check(
            "pilot_status",
            "The pilot completed without a pause.",
            "paused" if provenance.get("paused") else "completed",
            not bool(provenance.get("paused")),
        ),
    ]

    passed = all(item["pass"] for item in checks)
    if synthetic:
        verdict = "SELFTEST_ONLY"
    elif provenance.get("paused"):
        verdict = "PAUSED"
    elif reviewed < criteria["min_reviewed_alerts"]:
        verdict = "INCOMPLETE"
    else:
        verdict = "PASS" if passed else "FAIL"

    return {
        "phase": "S7",
        "evidence_status": (
            "SYNTHETIC SELF-TEST — NOT PILOT EVIDENCE"
            if synthetic
            else "REAL PILOT EXPORT — verify provenance and approvals before citing"
        ),
        "generated_from": (
            "SYNTHETIC SELF-TEST FIXTURE" if synthetic else str(directory)
        ),
        "provenance": provenance,
        "criteria": criteria,
        "summary": {
            "reviewed_alerts": reviewed,
            "queued_alerts": queued,
            "review_completion": review_completion,
            "eligible_flows": eligible_flows,
            "alerts_per_10k": alerts_per_10k,
            "alerts_per_10k_p95": alerts_per_10k_p95,
            "analysts": n_analysts,
            "days": day_count,
            "true_attack_yield": yield_value,
            "true_attack_yield_wilson_95": yield_interval,
            "disposition_counts": disposition_counts,
            "total_review_minutes": total_review_minutes,
            "fp_review_minutes": fp_minutes,
            "fp_minutes_share": fp_minutes_share,
            "confirmed_attacks": confirmed_attacks,
            "analyst_minutes_per_confirmed_attack": analyst_minutes_per_confirmed_attack,
            "missed_attacks": missed_count,
        },
        "onboarding": onboarding_metrics,
        "support": support_metrics,
        "cost": cost_metrics,
        "daily": daily.to_dict(orient="records"),
        "review_time_seconds": {
            "median": float(reviews["review_seconds"].median()),
            "p95": float(reviews["review_seconds"].quantile(0.95)),
            "max": float(reviews["review_seconds"].max()),
        },
        "checks": checks,
        "verdict": verdict,
        "interpretation": (
            "Synthetic self-test only. Do not cite as a pilot, a human study, or operational evidence."
            if synthetic
            else "A single-site pilot is scoped evidence. It does not establish 9/10 SaaS readiness or universal detection efficacy."
        ),
    }


def write_selftest_inputs(directory: Path) -> None:
    rng = np.random.default_rng(42)
    dates = pd.date_range("2026-01-05", periods=20, freq="B")
    rows = []
    alert_number = 0
    for day in dates:
        for analyst in ("analyst-a", "analyst-b"):
            for _ in range(11):
                alert_number += 1
                opened = day + pd.Timedelta(hours=9, minutes=alert_number % 300)
                disposition = rng.choice(
                    ["true_attack", "benign", "inconclusive", "duplicate"],
                    p=[0.62, 0.28, 0.07, 0.03],
                )
                seconds = float(rng.lognormal(mean=np.log(110), sigma=0.35))
                rows.append(
                    {
                        "alert_id": f"A{alert_number:05d}",
                        "analyst_id": analyst,
                        "date": day.date().isoformat(),
                        "opened_utc": opened.isoformat(),
                        "closed_utc": (opened + pd.Timedelta(seconds=seconds)).isoformat(),
                        "disposition": disposition,
                        "confidence": "medium",
                        "external_lookup": "no",
                        "escalated": "no",
                        "model_family": "unknown",
                    }
                )
    reviews = pd.DataFrame(rows)
    reviews.to_csv(directory / "reviews.csv", index=False)

    daily = pd.DataFrame(
        {
            "date": [day.date().isoformat() for day in dates],
            "eligible_flows": [110000] * len(dates),
            "alerts_queued": [22] * len(dates),
            "alerts_reviewed": [22] * len(dates),
            "unreviewed_due_to_cap": [0] * len(dates),
            "cap_hit": ["no"] * len(dates),
            "queue_latency_p50_s": [30] * len(dates),
            "queue_latency_p95_s": [75] * len(dates),
        }
    )
    daily.to_csv(directory / "daily.csv", index=False)

    onboarding = pd.DataFrame(
        {
            "participant_id": ["analyst-a", "analyst-b"],
            "role": ["analyst", "analyst"],
            "start_utc": ["2026-01-05T08:00:00Z", "2026-01-05T08:10:00Z"],
            "end_utc": ["2026-01-05T08:45:00Z", "2026-01-05T08:55:00Z"],
            "completed": [1, 1],
        }
    )
    onboarding.to_csv(directory / "onboarding.csv", index=False)

    ground_truth = reviews[["alert_id"]].copy()
    ground_truth["confirmed_attack"] = (
        reviews["disposition"].isin(["true_attack", "benign"]).astype(int)
    )
    ground_truth.to_csv(directory / "ground_truth.csv", index=False)

    pd.DataFrame(
        {
            "missed_id": ["M1", "M2"],
            "discovered_via": ["site telemetry", "incident review"],
            "confirmed_attack": [1, 1],
            "estimated_impact": ["not supplied", "not supplied"],
        }
    ).to_csv(directory / "missed_attacks.csv", index=False)

    pd.DataFrame(
        {
            "ticket_id": ["T1", "T2", "T3"],
            "opened_utc": ["2026-01-08T10:00:00Z", "2026-01-12T14:00:00Z", "2026-01-19T09:00:00Z"],
            "first_response_utc": ["2026-01-08T10:45:00Z", "2026-01-12T15:30:00Z", "2026-01-19T10:00:00Z"],
            "closed_utc": ["2026-01-08T12:00:00Z", "2026-01-12T18:00:00Z", "2026-01-19T11:00:00Z"],
            "severity": ["P3", "P2", "P3"],
            "category": ["console", "model output", "onboarding"],
        }
    ).to_csv(directory / "support.csv", index=False)

    (directory / "provenance.json").write_text(
        json.dumps(
            {
                "site": "SYNTHETIC SELF-TEST",
                "pilot_lead": "none",
                "start_date": dates[0].date().isoformat(),
                "end_date": dates[-1].date().isoformat(),
                "model_version": "serving-lr-day-based-seed42-v1",
                "artifact_sha256": "synthetic",
                "feature_schema": "cic-ids-2017-80f-45cd75ce849b",
                "threshold_policy": "frozen",
                "calibration_version": "uncalibrated",
                "model_changes": 0,
                "paused": False,
                "approval_date": "none",
                "approver": "none",
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (directory / "costs.json").write_text(
        json.dumps(
            {"currency": "USD", "analyst_hourly_cost": None, "missed_attack_cost": None},
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir")
    parser.add_argument("--output", default="docs/s7_pilot_analysis.json")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        temp = Path(tempfile.mkdtemp(prefix="s7_selftest_"))
        write_selftest_inputs(temp)
        result = analyze(temp, synthetic=True)
    elif args.input_dir:
        result = analyze(Path(args.input_dir), synthetic=False)
    else:
        raise SystemExit("provide --input-dir or --self-test")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2 if args.pretty else None, default=str) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote {output}")
    print(f"Verdict: {result['verdict']}")
    for item in result["checks"]:
        print(f"  [{'PASS' if item['pass'] else 'FAIL'}] {item['id']}: {item['observed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
