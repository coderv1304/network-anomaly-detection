# S7 — Design-Partner Pilot Outcome

**Status:** **NOT RUN. BLOCKED. There are no pilot results.**
**Date:** 2026-11-11.
**Protocol:** [`S7_PILOT_PREREGISTRATION.md`](S7_PILOT_PREREGISTRATION.md).
**Analysis harness:** `scripts/pilot_analysis.py`.
**Harness self-test:** [`s7_pilot_analysis_selftest.json`](s7_pilot_analysis_selftest.json) — **synthetic, not evidence.**

## 1. Honest summary

| Requested outcome | Actual status |
| --- | --- |
| A design partner with a real team | **No partner.** No organization has been recruited or consented. |
| Measured onboarding time | **Not measured.** Only the protocol and export schema exist. |
| Measured alert yield | **Not measured.** No real queue, no analyst dispositions. |
| Measured analyst time per alert | **Not measured.** The 5-minute assumption in D9 remains an assumption. |
| Measured false-positive cost | **Not measured.** No site costs and no review logs. |
| Measured support load | **Not measured.** No support tickets. |
| Console/workflow/model feedback | **Not collected.** No participants, no survey, no interviews. |
| A pilot outcome report | **This document is the outcome: no pilot exists.** |

**The S7 exit gate is not met.** The work completed here is the pre-registration, the instruments, the export schemas, and a tested analysis harness. That is preparation for evidence, not evidence.

## 2. Why the pilot could not be run

The assistant cannot recruit a design partner, obtain site consent, approve data handling, or observe real analysts. Running a "pilot" on synthetic or replayed data and labelling it as a design-partner pilot would be fabrication. The blockers are therefore reported rather than worked around.

| Blocker | Consequence |
| --- | --- |
| No design partner or signed approval | No lawful or ethical access to a real team or its traffic. |
| No data-handling review | Capturing a site's traffic without approval is not acceptable. |
| Served artifact identity | **Resolved.** The pilot would measure the same RF seed 42 artifact that is now evaluated and gated. Before this fix the pilot would have measured the legacy serving LR. See [`COST_MODEL_AND_RELEASE_GATE.md`](COST_MODEL_AND_RELEASE_GATE.md). |
| No external validation | A single-site pilot cannot repair the missing external-dataset gate. |
| No sustained SLO evidence | The 20 flows/s latency SLO now passes once, but a multi-hour sustained run and higher-rate capacity are unproven; a pilot would measure an under-characterized product. |
| No support capacity | There is no on-call rotation or support SLA to absorb pilot tickets. |
| No consent-safe capture path for a partner | The current capture tooling is a research prototype, not a managed tenant deployment. |

The correct sequence is: reduce false-positive/alert-budget behaviour, complete an external dataset and security review, then recruit a partner under written approval. Artifact identity is already resolved.

## 3. What was actually built

### 3.1 Pre-registration

[`S7_PILOT_PREREGISTRATION.md`](S7_PILOT_PREREGISTRATION.md) fixes the design before any data exists:

- 4-week single-site pilot, 2 analysts, 2-day run-in;
- 100 alerts per 10,000 flows and 40 alerts per analyst per day;
- 17 success criteria covering onboarding, budget, review completion, analyst time, yield, FP cost, support load, model stability, and data integrity;
- explicit failure and stop rules;
- a statement that a single pilot cannot support 9/10 SaaS readiness.

The criteria were written before any pilot data and are not adjusted after seeing results.

### 3.2 Instruments and export schemas

The protocol defines:

- disposition rubric (`true_attack`, `benign`, `inconclusive`, `duplicate`, `out_of_scope`);
- required review fields and escalation rules;
- weekly 1–5 surveys and structured interviews for console, workflow, model output, trust, workload, and support;
- CSV/JSON schemas for onboarding, daily queue, reviews, ground truth, missed attacks, support, costs, and provenance.

These are the instruments a future pilot would use. They are not results.

### 3.3 Analysis harness

`scripts/pilot_analysis.py` computes the predeclared metrics from exported logs:

- onboarding median/p95 and completion;
- daily alert rate per 10,000 flows and p95;
- review completion and queue latency;
- review-time median/p95/max;
- disposition counts, true-positive yield, Wilson interval;
- FP review minutes and share;
- analyst minutes per confirmed attack;
- missed attacks;
- support tickets per analyst-week, first response, resolution, P1 breaches;
- site-supplied cost calculation, only when the site supplies real figures.

It writes a machine-readable result and prints a PASS/FAIL table. It refuses to label synthetic input as real evidence.

### 3.4 Self-test (not a pilot)

The harness was run on a synthetic 20-day fixture to prove the code path:

| Field | Value |
| --- | --- |
| Evidence status | `SYNTHETIC SELF-TEST — NOT PILOT EVIDENCE` |
| Verdict | `SELFTEST_ONLY` |
| Synthetic reviewed alerts | 440 |
| Synthetic analysts | 2 |
| Synthetic days | 20 |
| All checks | pass on the synthetic fixture |

**This says nothing about the product.** It only shows that the calculations execute and that the gate can fail or pass as designed. The fixture was generated by the harness itself, not collected from people. It must never be cited as onboarding time, yield, analyst time, support load, or customer evidence.

## 4. What the pilot would have measured

For clarity, these are the quantities that remain unknown:

| Quantity | Why it matters | Current status |
| --- | --- | --- |
| Time to first meaningful review | Predicts onboarding friction and deployment cost | Unknown |
| Alerts per 10,000 flows in a real network | Tests whether the offline budget transfers | Unknown |
| Analyst minutes per alert | Replaces the D9 5-minute assumption | Unknown |
| True-positive yield on site traffic | Tests whether offline precision survives | Unknown |
| FP review-time share | Measures the real cost of false positives | Unknown |
| Missed attacks found outside the queue | Measures the cost of low recall | Unknown |
| Support tickets per analyst-week | Measures operational drag | Unknown |
| Console/workflow feedback | Tests whether the UI helps or obstructs | Unknown |
| Model-output trust | Tests whether analysts act on the score | Unknown |

Without these, claims about analyst savings, ROI, operational effectiveness, or SaaS readiness are unsupported.

## 5. What cannot be claimed

Do not claim any of the following:

- that S7 is complete;
- that a design partner used the product;
- that onboarding takes a certain number of minutes;
- that the queue yields a certain percentage of attacks;
- that analysts save time;
- that support load is acceptable;
- that the console is usable in a real SOC;
- that the product is operationally effective or production ready;
- that the product is 9/10 SaaS;
- that a single pilot would prove any of the above even if it passed.

The scorecard does not move. Production SaaS remains **3/10**.

## 6. What would unblock S7

1. Serve, evaluate, and gate the same artifact. **Done:** the registry-active seed 42 RF hash matches the evaluated manifest.
2. Reduce false positives and alert volume to a defensible operating point, or explicitly adopt a queue policy and measure it.
3. Complete an independent external-dataset evaluation.
4. Commission the external penetration test and resolve critical/high findings.
5. Provide managed secrets, a real IdP integration, operated off-host encrypted backup with measured RPO/RTO, an operated staging environment, and production migration history.
6. Measure sustained SLO compliance rather than one 20 flows/s run.
7. Recruit a design partner with written approval and a data-handling note.
8. Freeze the release manifest and run the pre-registered pilot.
9. Publish the outcome with all failures, including days the cap was hit and attacks the queue missed.
10. Keep the result scoped to one site. A successful pilot is evidence of usability at that site, not proof of universal detection or 9/10 SaaS.

## 7. Verdict

**S7 is blocked and not run. The exit gate is not met. Production SaaS stays at 3/10. No customer, price, SLA, yield, onboarding time, analyst saving, or support-load claim is supported.**
