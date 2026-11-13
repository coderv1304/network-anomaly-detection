# D8 — Prospective Human-Review Pilot Protocol

**Status:** protocol only. **No human pilot has been run.** Nothing in this document is an operational result.
**Date:** 2026-11-10.
**Related:** [`ALERT_BURDEN_AND_FEEDBACK.md`](ALERT_BURDEN_AND_FEEDBACK.md), [`FEEDBACK_SIMULATION.md`](FEEDBACK_SIMULATION.md), [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md), [`S7_PILOT_PREREGISTRATION.md`](S7_PILOT_PREREGISTRATION.md).

## 1. Why this pilot exists

The offline and simulated-feedback results answer a model question, not an analyst question. They do not measure:

- how long a person needs to judge one alert;
- how many alerts a person can review per day without skipping;
- what a false positive costs in analyst time and disruption;
- what a missed attack costs when the queue is full;
- whether the alert budget is usable by a real team.

This protocol measures those quantities. It is deliberately separate from the simulated analyst feedback in [`FEEDBACK_SIMULATION.md`](FEEDBACK_SIMULATION.md). **Simulated feedback is not a human study and cannot be reported as one.**

## 2. Preconditions before a pilot may start

A pilot may not start unless all of the following are true:

1. The serving artifact, feature schema, threshold policy, and evaluation artifact are the same versioned release.
2. The deployment has a working backup/restore drill and an incident-response owner.
3. The alert queue is read-only and cannot block, quarantine, or modify hosts.
4. Participants have written instructions and a way to stop the pilot.
5. The data-handling review is complete: what is captured, where it is stored, who can read it, and how it is deleted.
6. The pilot is approved by the site owner, not by the model owner alone.

If any precondition fails, the pilot is postponed. Do not substitute a demo or a replay.

## 3. Design

| Item | Design |
| --- | --- |
| Type | Prospective, single-site, human-in-the-loop observational pilot |
| Duration | 4 consecutive weeks (20 working days), with a 2-day run-in |
| Traffic | Live traffic from one consented site or lab segment, not CIC-IDS-2017 replay |
| Analysts | 2 analysts, trained on the same rubric; at least 1 independent reviewer for disagreements |
| Alert budget | 100 alerts per 10,000 eligible flows, capped at 40 alerts per analyst per day |
| Queue | Chronological priority queue with model score, flow metadata, and no model explanation unless produced by the served path |
| Model | Frozen for the whole pilot; no online learning, no threshold changes |
| Threshold | Frozen from the release; never retuned during the pilot |
| Labels | Analyst decision recorded before the answer is known; later ground truth from the site's own telemetry or incident review |

### 3.1 Run-in

The first two days are used to:

- verify that the queue, login, audit log, and export work;
- calibrate the analysts on 20 practice alerts that are **not** part of the analysis;
- measure and fix queue latency.

Run-in data are excluded from the primary analysis. Any change made during run-in is versioned and the pilot restarts.

### 3.2 Sampling and alert budget

- The queue is capped at **100 alerts per 10,000 eligible flows** and **40 alerts per analyst per day**, whichever is lower.
- If the cap is reached, the remaining flows are not shown. The number of unreviewed flows is recorded.
- The budget is fixed before the pilot. It is not changed because the first week looks quiet or noisy.
- The queue is not filled with low-score flows to hit the cap. Under-fill is recorded as under-fill.

### 3.3 Review queue fields

Each row shows only:

- alert id, timestamp, source/destination (masked according to site policy), protocol, ports;
- flow duration, packet/byte counts, and the model's attack score;
- the model version, feature-schema version, threshold policy, and calibration version;
- review status and reviewer note.

It does **not** show a fabricated explanation, threat attribution, or severity that the served path did not compute.

### 3.4 Labelling instructions

The analyst chooses exactly one disposition:

| Disposition | Meaning |
| --- | --- |
| `true_attack` | The flow is part of a real attack or unwanted activity. |
| `benign` | The flow is normal or authorised. |
| `inconclusive` | The evidence is insufficient; do not guess. |
| `duplicate` | The same incident was already reviewed. |
| `out_of_scope` | The flow is not covered by the pilot's consent or policy. |

Required fields: disposition, confidence (`low`/`medium`/`high`), free-text reason, time started, time finished, and whether the analyst used an external lookup. The reason is capped at 500 characters. The analyst must not see the model's argmax family label as if it were ground truth.

### 3.5 Escalation rules

| Trigger | Action | Owner | Target |
| --- | --- | --- | --- |
| `true_attack` with high confidence and active exploitation signs | Open a site incident ticket; notify the duty owner | Analyst → duty owner | 30 min |
| Repeated `true_attack` on one host in 24 h | Group into one incident; stop duplicating alerts | Duty owner | 4 h |
| Queue backlog > 1 day | Reduce non-critical ingestion or raise the cap only with written approval; record the decision | Pilot lead | Same day |
| Suspected data breach or credential exposure | Follow the incident-response runbook; preserve logs; do not delete evidence | Security owner | 1 h |
| Analyst cannot review safely | Pause the pilot; record why | Pilot lead | Immediate |

## 4. Metrics

### 4.1 Primary metrics

| Metric | Definition | Unit |
| --- | --- | --- |
| Analyst time per alert | Median and p95 wall-clock time from opening to disposition | seconds |
| True-positive yield | `true_attack` alerts / reviewed alerts | proportion |
| False-positive cost | Analyst minutes on `benign` + `inconclusive` + `duplicate` alerts | minutes |
| Missed-attack cost | Confirmed attacks not shown in the queue, with site-estimated impact | count and qualitative cost |
| Alert volume | Alerts shown per day and per 10,000 eligible flows | count |
| Review completion | Reviewed alerts / queued alerts | proportion |
| Queue latency | Time from flow to first display | seconds |

### 4.2 Secondary metrics

- Disposition agreement between analysts (Cohen's kappa).
- Time to escalation for true attacks.
- Share of alerts that required an external lookup.
- Share of alerts marked `out_of_scope`.
- Analyst-reported workload (1–5) at the end of each day.
- Number of threshold or model changes (target: zero).
- Number of unreviewed flows due to the cap.

### 4.3 Cost model

Record the site's own fully loaded analyst cost per hour and the site's estimate of a missed-attack impact. Do not invent a dollar value. If the site cannot provide one, report the metrics without a monetary cost and say so.

## 5. Analysis plan

- Report by day and by attack family; do not aggregate away a bad day.
- Report medians and p95, not only means.
- Report Wilson intervals for proportions and bootstrap intervals for time metrics where support permits.
- Compare the first week with the last week only as an operational learning curve, not as a model improvement.
- Report all dispositions, including `inconclusive` and `duplicate`.
- Do not compare pilot yield to CIC-IDS-2017 precision or recall as if the populations were the same.
- Do not claim operational effectiveness, analyst savings, or ROI before the outcome report is written and reviewed.

## 6. Stop criteria

Pause the pilot if any of the following occurs:

- a suspected breach or data-handling incident;
- the queue cannot be reviewed within the daily cap for 3 consecutive days;
- the model or threshold changes;
- the site withdraws consent;
- an analyst cannot follow the rubric safely.

A paused pilot is reported as paused, with the reason and the data collected so far. It is not silently extended.

## 7. Deliverables

1. Signed pilot approval and data-handling note.
2. Versioned release manifest (artifact, schema, threshold, calibration).
3. Daily queue and analyst logs, exported from the application, not retyped.
4. Incident tickets and escalation timestamps.
5. Outcome report using [`D8_PILOT_OUTCOME_TEMPLATE.md`](D8_PILOT_OUTCOME_TEMPLATE.md).
6. A written limitations section that states the pilot is single-site and not a universal efficacy claim.

## 8. What this protocol does not do

- It does not create a pilot.
- It does not make the current detector operationally validated.
- It does not convert simulated feedback into human evidence.
- It does not authorise blocking, quarantine, or automated response.
