# D8 — Prospective Pilot Outcome Report Template

**Status:** **template only. No pilot has been run. Do not fill this in with simulated or imagined data.**
**Date:** 2026-11-10.
**Protocol:** [`D8_PROSPECTIVE_PILOT_PROTOCOL.md`](D8_PROSPECTIVE_PILOT_PROTOCOL.md).

> Before this template is used, the protocol's preconditions must all be true, the pilot must have been approved by the site owner, and the release manifest must be frozen. If the pilot was not run, this document stays a template and is reported as such.

## 0. Provenance block (required)

| Field | Value |
| --- | --- |
| Site / segment | `<fill in>` |
| Pilot lead | `<fill in>` |
| Approval date and approver | `<fill in>` |
| Start / end date | `<fill in>` |
| Days analysed (excluding run-in) | `<fill in>` |
| Model version | `<fill in>` |
| Artifact SHA-256 | `<fill in>` |
| Feature schema version | `<fill in>` |
| Threshold and policy | `<fill in>` |
| Calibration version | `<fill in>` |
| Model/threshold changes during pilot | `<none, or list>` |
| Was the pilot paused? | `<no / yes — reason>` |

## 1. Executive summary

- What was measured: `<one paragraph>`
- Did the alert budget hold? `<yes/no, with the number>`
- True-positive yield: `<proportion and interval>`
- Did the pilot meet its own predeclared success criteria? `<yes/no/partly — link the criteria>`
- What cannot be concluded from this pilot: `<single-site, single-artifact, limited duration, etc.>`

**Do not write "operationally effective", "production ready", or an ROI number unless the data below directly supports it.**

## 2. Data and exclusions

| Item | Value |
| --- | --- |
| Eligible flows | `<count>` |
| Alerts queued | `<count>` |
| Alerts reviewed | `<count>` |
| Unreviewed because of the cap | `<count>` |
| Run-in alerts excluded | `<count>` |
| Out-of-scope alerts | `<count>` |
| Duplicate alerts | `<count>` |
| Data-quality exclusions (and why) | `<list>` |

## 3. Alert volume and queue behaviour

| Metric | Median | p95 | Max |
| --- | --- | --- | --- |
| Alerts shown per day | `<...>` | `<...>` | `<...>` |
| Alerts per 10,000 eligible flows | `<...>` | `<...>` | `<...>` |
| Queue latency (flow → first display, s) | `<...>` | `<...>` | `<...>` |
| Review completion (%) | `<...>` | `<...>` | `<...>` |

Days the 40-alert/analyst daily cap was hit: `<list dates and hours>`.

## 4. Analyst time

| Metric | Value |
| --- | --- |
| Analysts | `<count>` |
| Median time per alert (s) | `<...>` |
| p95 time per alert (s) | `<...>` |
| Total analyst minutes | `<...>` |
| Minutes on benign alerts | `<...>` |
| Minutes on inconclusive alerts | `<...>` |
| Minutes on duplicates | `<...>` |
| End-of-day workload (1–5), mean | `<...>` |

## 5. Dispositions and yield

| Disposition | Count | Share | Wilson 95% |
| --- | ---: | ---: | --- |
| `true_attack` | `<...>` | `<...>` | `<...>` |
| `benign` | `<...>` | `<...>` | `<...>` |
| `inconclusive` | `<...>` | `<...>` | `<...>` |
| `duplicate` | `<...>` | `<...>` | `<...>` |
| `out_of_scope` | `<...>` | `<...>` | `<...>` |

- True-positive yield (`true_attack` / reviewed): `<...>`
- False-positive cost (minutes on `benign` + `inconclusive` + `duplicate`): `<...>`
- Inter-analyst agreement (Cohen's kappa): `<...>`

## 6. By day and by family

| Day | Alerts | Reviewed | `true_attack` | Yield | Median review s | Cap hit? |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `<date>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<yes/no>` |

| Model family label | Alerts | Confirmed attacks | Analyst-confirmed benign | Notes |
| --- | ---: | ---: | ---: | --- |
| `<family>` | `<...>` | `<...>` | `<...>` | `<...>` |

Report every day. Do not aggregate away a bad day.

## 7. Missed attacks

| Item | Value |
| --- | --- |
| Confirmed attacks not shown in the queue | `<count>` |
| How they were discovered | `<site telemetry / incident review / other>` |
| Site-estimated impact | `<qualitative; monetary only if the site supplied it>` |
| Root-cause note (budget cap, threshold, feature gap, unseen family) | `<...>` |

## 8. Escalations and incidents

| Time | Alert/incident | Trigger | Escalated to | Time to escalate | Outcome |
| --- | --- | --- | --- | --- | --- |
| `<...>` | `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

## 9. Cost (only if the site supplied real figures)

| Item | Value | Source |
| --- | --- | --- |
| Fully loaded analyst cost per hour | `<...>` | `<site finance/HR>` |
| Analyst cost for the pilot | `<...>` | derived |
| Estimated missed-attack cost | `<...>` | `<site risk owner>` |
| Net position | `<...>` | derived, with method stated |

If the site cannot supply these, write "not supplied" and omit the monetary section. **Never invent a dollar value.**

## 10. Deviations from protocol

| Deviation | Why | Effect on interpretation |
| --- | --- | --- |
| `<...>` | `<...>` | `<...>` |

## 11. Limitations

- Single site, `<n>` analysts, `<n>` weeks.
- One frozen artifact and threshold.
- Alert budget fixed in advance; results do not generalize to other budgets.
- Ground truth quality: `<describe source and gaps>`.
- The model is uncalibrated in the serving path unless the manifest says otherwise.
- This pilot does not validate other traffic, other sites, or other attack families.
- Simulated feedback in [`FEEDBACK_SIMULATION.md`](FEEDBACK_SIMULATION.md) is **not** part of this result.

## 12. Verdict

- Does this pilot support an operational-effectiveness claim? `<yes/no — and for which scope only>`
- Does it change the detection score? `<state honestly; a single-site pilot usually does not>`
- What is the next experiment? `<...>`

## 13. Attachments

- [ ] Signed pilot approval and data-handling note
- [ ] Frozen release manifest
- [ ] Exported daily queue logs (not retyped)
- [ ] Exported analyst disposition logs
- [ ] Incident tickets and escalation timestamps
- [ ] Analysis script / notebook used to compute the tables above
