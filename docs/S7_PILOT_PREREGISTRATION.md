# S7 — Design-Partner Pilot: Pre-Registration and Instruments

**Status:** **pre-registered protocol and analysis harness only. No design partner has been recruited and no pilot has been run.** Nothing here is a pilot result.
**Date:** 2026-11-11.
**Extends:** [`D8_PROSPECTIVE_PILOT_PROTOCOL.md`](D8_PROSPECTIVE_PILOT_PROTOCOL.md), which defines the prospective human-review method. S7 adds predeclared commercial and workflow success criteria, export schemas, and an analysis script.
**Evidence status:** **not run / blocked.** See [`S7_PILOT_OUTCOME.md`](S7_PILOT_OUTCOME.md).
**Analysis harness:** `scripts/pilot_analysis.py`.

## 1. Why S7 exists

D8 answers "can analysts use the queue safely?" S7 answers the harder product question:

- How long does a real team need to get productive?
- What is the alert yield in the team's own traffic?
- How many analyst minutes does one alert cost?
- How much support load does the product create?
- Does the console and review workflow help, confuse, or obstruct the analyst?
- Does the model output earn trust, or is it ignored?

These are measured outcomes, not features. A checklist, a demo, or a simulated analyst cannot establish them. **This protocol does not create a pilot.**

## 2. Non-negotiable preconditions

A pilot may not start until all of the following are true. If any is false, the pilot is postponed rather than improvised.

1. A named design partner has signed a pilot approval and data-handling note.
2. The serving artifact, feature schema, threshold policy, and calibration version are frozen and recorded in a release manifest.
3. The exact served artifact has been evaluated on a held-out partition, and its artifact hash matches the registry entry.
4. The site has a working backup/restore drill and an incident-response owner.
5. The queue is read-only: it cannot block, quarantine, or modify a host.
6. Participants have written instructions, a stop mechanism, and a named escalation contact.
7. The site has stated whether it will supply `C_FP`, `C_FN`, and an analyst review budget. "Not supplied" is allowed, but the monetary analysis will then be omitted.
8. The pilot lead is not the model owner alone.

## 3. Design

| Item | Predeclared design |
| --- | --- |
| Type | Prospective, single-site, human-in-the-loop observational pilot |
| Duration | 4 consecutive weeks (20 working days), plus a 2-day run-in |
| Traffic | The site's live traffic on one consented segment, not a CIC-IDS-2017 replay |
| Analysts | 2 analysts trained on the same rubric; one independent reviewer for disagreements |
| Alert budget | 100 alerts per 10,000 eligible flows, capped at 40 alerts per analyst per day |
| Queue | Chronological priority queue with score, flow metadata, model version, schema, threshold policy, and calibration version |
| Model | Frozen for the pilot; no online learning, no threshold changes, no model swap |
| Labels | Analyst disposition recorded before ground truth is known; later adjudication from site telemetry or incident review |
| Run-in | First 2 days excluded from the primary analysis; used to fix queue latency and train analysts on 20 practice alerts |
| Changes | Any change during run-in restarts the pilot and is versioned |

### 3.1 Sampling and queue rules

- The queue is capped at the lower of 100 alerts per 10,000 eligible flows and 40 alerts per analyst per day.
- If the cap is reached, remaining flows are not shown; the number is recorded as `unreviewed_due_to_cap`.
- The queue is never filled with low-score flows to hit the cap. Under-fill is recorded.
- The budget is fixed before the pilot and is not changed because week 1 looks quiet or noisy.

### 3.2 Review fields and dispositions

Each alert shows only the alert id, timestamp, masked endpoints, protocol, ports, flow duration, packet/byte counts, attack score, model/schema/threshold/calibration versions, and the review fields.

The analyst chooses exactly one disposition:

| Disposition | Meaning |
| --- | --- |
| `true_attack` | The flow is part of a real attack or unwanted activity. |
| `benign` | The flow is normal or authorised. |
| `inconclusive` | The evidence is insufficient; do not guess. |
| `duplicate` | The same incident was already reviewed. |
| `out_of_scope` | The flow is outside the consented scope. |

Required review fields: disposition, confidence (`low`/`medium`/`high`), reason (≤500 chars), opened time, closed time, external-lookup flag, escalation flag. The analyst must not be shown the model's argmax family label as if it were ground truth.

### 3.3 Feedback instruments

At the end of each week, each participant completes a 1–5 Likert survey and a 20-minute structured interview. Record verbatim comments, not just scores.

| Instrument | Questions |
| --- | --- |
| Console | Could you find the queue, filter it, and understand why a flow was shown? (1–5) |
| Workflow | Did the disposition flow match how you actually triage? (1–5) |
| Model output | Was the attack score useful, misleading, or ignored? (1–5 plus free text) |
| Trust | Would you act on this alert without a second opinion? (1–5) |
| Workload | Was the daily alert volume manageable? (1–5) |
| Support | Was help available when you needed it? (1–5) |
| Failure log | Describe one thing the product made harder, not easier. |

Survey scores are **secondary** and cannot override the measured queue, time, yield, cost, and support outcomes.

## 4. Predeclared success criteria

These criteria are fixed before the pilot. They are stored in `criteria.json` and read by `scripts/pilot_analysis.py`. A criterion is not changed after seeing the data.

| ID | Criterion | Threshold | Rationale |
| --- | --- | ---: | --- |
| S7-01 | Reviewed alerts | ≥ 300 | Below this, yield and time estimates are too unstable to gate. |
| S7-02 | Onboarding median | ≤ 60 minutes | A team must reach a first meaningful review within an hour. |
| S7-03 | Onboarding completion | ≥ 90% of participants | One failed participant is a product problem, not a training footnote. |
| S7-04 | Daily alert rate p95 | ≤ 100 per 10,000 flows | Matches the predeclared budget. |
| S7-05 | Review completion | ≥ 95% of queued alerts | A queue that is not reviewed is not a queue. |
| S7-06 | Median review time | ≤ 180 seconds | The model must not turn triage into forensic investigation. |
| S7-07 | p95 review time | ≤ 600 seconds | A long tail of confusing alerts is an operational cost. |
| S7-08 | True-positive yield | ≥ 50% | At least half the reviewed alerts must be real attacks. |
| S7-09 | Yield Wilson lower bound | ≥ 40% | The minimum must survive sampling uncertainty. |
| S7-10 | FP review-time share | ≤ 50% of total review time | False positives must not consume most of the analyst day. |
| S7-11 | Analyst minutes per confirmed attack | ≤ 6.0 minutes | The queue must be economically plausible at the site's costs. |
| S7-12 | Support tickets | ≤ 2 per analyst-week | High support load is a product failure even if the model is accurate. |
| S7-13 | Median first response | ≤ 4 business hours | A pilot without timely support measures the wrong product. |
| S7-14 | P1 unresolved > 24h | 0 | Critical support failures stop the pilot. |
| S7-15 | Model/threshold changes | 0 | A mid-pilot change destroys comparability. |
| S7-16 | Pilot interruptions | 0 pauses | A paused pilot is reported as paused, not extended silently. |
| S7-17 | Data integrity | Required fields present; no duplicate alert IDs; no negative durations | Bad exports cannot become evidence. |

**Pass rule:** all criteria pass, the pilot completed without a pause, and at least 300 alerts were reviewed. Otherwise the verdict is `FAIL`, `INCOMPLETE`, or `PAUSED`. A partial pass is not a pass.

**Power and precision:** 300 reviewed alerts gives a 95% Wilson half-width of roughly ±5.7 percentage points at a 50% yield, and about ±5.0 points at 60–70% yield. This is enough to reject a grossly unusable queue, not enough to estimate a precise yield or to generalise to other sites. The pilot is explicitly single-site.

## 5. Metrics and formulas

Let `reviewed` be alerts with a completed disposition, `queued` the alerts shown, and `eligible_flows` the site's eligible flow count.

| Metric | Formula |
| --- | --- |
| Onboarding time | `closed_utc - start_utc` per participant; report median and p95 |
| Alert rate per 10k | `queued / eligible_flows × 10,000`; report median and p95 by day |
| Review completion | `reviewed / queued` |
| Review time | `closed_utc - opened_utc`; report median, p95, max |
| True-positive yield | `count(disposition = true_attack) / reviewed`, with Wilson 95% |
| False-positive review time | minutes on `benign` + `inconclusive` + `duplicate` + `out_of_scope` |
| FP share | FP review minutes / total review minutes |
| Analyst minutes per confirmed attack | total review minutes / adjudicated confirmed attacks |
| Missed attacks | confirmed attacks found by site telemetry or incident review but not shown in the queue |
| Support load | tickets / (analysts × weeks); median first-response and resolution hours; P1 open >24h |
| Cost | `total review hours × site hourly rate`; missed cost only if the site supplies it |

All durations use wall-clock UTC timestamps exported from the application. Do not retype logs. Do not use the model's score as a label.

## 6. Export schemas

The analysis harness expects one directory containing:

| File | Required | Columns |
| --- | --- | --- |
| `provenance.json` | yes | site, pilot_lead, start_date, end_date, model_version, artifact_sha256, feature_schema, threshold_policy, calibration_version, model_changes, paused, approval_date, approver |
| `onboarding.csv` | yes | participant_id, role, start_utc, end_utc, completed |
| `daily.csv` | yes | date, eligible_flows, alerts_queued, alerts_reviewed, unreviewed_due_to_cap, cap_hit, queue_latency_p50_s, queue_latency_p95_s |
| `reviews.csv` | yes | alert_id, analyst_id, date, opened_utc, closed_utc, disposition, confidence, external_lookup, escalated, model_family |
| `ground_truth.csv` | recommended | alert_id, confirmed_attack |
| `missed_attacks.csv` | recommended | missed_id, discovered_via, confirmed_attack, estimated_impact |
| `support.csv` | yes | ticket_id, opened_utc, first_response_utc, closed_utc, severity, category |
| `costs.json` | optional | analyst_hourly_cost, missed_attack_cost, currency; use `null` if not supplied |
| `criteria.json` | optional | Override of the predeclared gates; the committed defaults are the gate |

The harness treats duplicate alert IDs, unknown dispositions, and negative durations as data-integrity failures. The analysis aborts with a clear error when required columns are missing. It does not silently repair any of these.

## 7. Analysis plan

1. Report every day, including bad days. Do not aggregate away a failure.
2. Report medians and p95, not only means.
3. Report Wilson intervals for yield and bootstrap intervals for time metrics where support permits.
4. Report all dispositions, including `inconclusive`, `duplicate`, and `out_of_scope`.
5. Compare week 1 with week 4 only as an operational learning curve, never as a model improvement.
6. Report the survey and interview feedback separately from the measured outcomes. A positive survey cannot rescue a failed yield gate.
7. Do not compare pilot yield to CIC-IDS-2017 precision or recall as if the populations were the same.
8. Do not claim operational effectiveness, analyst savings, ROI, or 9/10 SaaS readiness before the outcome report is written and reviewed.

## 8. Stop criteria

Pause and report the pilot as paused if any of the following occurs:

- a suspected breach or data-handling incident;
- the queue cannot be reviewed within the daily cap for 3 consecutive days;
- the model, threshold, or feature schema changes;
- the site withdraws consent;
- an analyst cannot follow the rubric safely;
- a P1 support issue remains unresolved beyond 24 hours.

Do not extend a paused pilot silently to recover a sample-size target.

## 9. What would count as failure

The pilot fails honestly if any of these occurs, even if the console looks polished:

- fewer than 300 reviewed alerts;
- yield below 50% or a Wilson lower bound below 40%;
- median review time above 3 minutes or p95 above 10 minutes;
- FP review time above half the analyst day;
- more than 2 support tickets per analyst-week;
- any unresolved P1 beyond 24 hours;
- a model or threshold change during the pilot;
- an inability to export clean logs.

A failure is a product finding, not a reason to lower the gate after the fact.

## 10. What this protocol cannot establish

- It cannot establish universal detection accuracy from one site.
- It cannot establish 9/10 SaaS readiness from one pilot, even a successful one.
- It cannot convert simulated analyst feedback into human evidence.
- It cannot substitute for an external penetration test, managed secrets, a real IdP integration, off-host backup, an operated staging environment, or measured SLO compliance.
- It cannot invent a price, a customer, or a support SLA.

## 11. Reproduction

```bash
# Self-test the analysis harness on synthetic data. This is not pilot evidence.
venv/Scripts/python.exe scripts/pilot_analysis.py \
  --self-test \
  --output docs/s7_pilot_analysis_selftest.json

# Analyse a real, approved export. Do not run this on synthetic data and cite it.
venv/Scripts/python.exe scripts/pilot_analysis.py \
  --input-dir path/to/pilot_export \
  --output docs/s7_pilot_analysis.json
```

The self-test output is stored in [`s7_pilot_analysis_selftest.json`](s7_pilot_analysis_selftest.json) with `evidence_status: SYNTHETIC SELF-TEST — NOT PILOT EVIDENCE` and verdict `SELFTEST_ONLY`.
