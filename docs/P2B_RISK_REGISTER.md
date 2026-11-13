# P2B Risk Register

**Status:** active. **Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Date:** 2026-11-13.
**Evidence:** [`p2b_protocol_analysis.json`](p2b_protocol_analysis.json), [`P2B_PROTOCOL_ANALYSIS.md`](P2B_PROTOCOL_ANALYSIS.md), [`VOLUMETRIC_MODEL.json`](VOLUMETRIC_MODEL.json).
**Residual acceptance:** [`P2B_RESIDUAL_RISK_ACCEPTANCE.md`](P2B_RESIDUAL_RISK_ACCEPTANCE.md) — disposition of the residuals that the controls do not remove; applies only to the blocked phase.
**Rule:** every risk has an owner, a trigger, and a residual. A risk without a trigger is an opinion, not a control.

This register responds to the six risks recorded after the P2B protocol audit. It does
not change the phase status: P2B remains **blocked**, no model or registry row exists,
and the serving artifact is untouched.

## Rating

| Rating | Meaning |
| --- | --- |
| Critical | Invalidates the primary claim or a gate if unmanaged. |
| High | Can mislead a reader, a reviewer, or a release decision. |
| Medium | Costs time or precision but does not invalidate the claim. |

Likelihood is **certain** when the condition is already observed in the data,
**likely** when it follows from the design, and **possible** when it depends on
future behaviour.

## Register

| ID | Risk | Severity | Likelihood | Response | Owner | Trigger | Residual |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R1 | Validation partition is not representative of the test families. | Critical | Certain | Coverage gate; A4 or zero-shot A1f; no threshold transport. | Research lead | Any split failing the gate: no training. | Temporal drift and family imbalance remain even when coverage passes. |
| R2 | DDoS/PortScan have no training or validation rows; Friday metrics are zero-shot. | Critical | Certain | No per-family heads; label every DDoS/PortScan result zero-shot; report exact upper bounds. | ML evaluation engineer | Any sentence implying validated DDoS/PortScan detection. | Zero-shot estimates may be uninformative; A4 required for validation. |
| R3 | Thursday–Friday has already been inspected; it is not a blind confirmatory test. | High | Certain | Treat as development test; one-touch run log; acquire an external confirmatory set. | Evaluation engineer | Any test access without a frozen protocol. | No blind test until external data or capture. |
| R4 | At 10/100 alerts per 10k, per-family counts are small and CIs are wide. | High | Likely | Minimum-reportable-count rule; exact intervals; raw counts; precision calculation before the run. | Applied statistician | Fewer than 10 alerts for a family. | Low power at 10/10k is inherent; more alerts or more data are the only fixes. |
| R5 | Tier B fan-out, external datasets, real capture, pilot, and pen test are absent. | Critical | Certain | Dependency register with entry criteria; no synthetic substitutes. | Research operations lead | Phase entry criteria not met. | Schedule and cost risk; external dependencies. |
| R6 | A future result is over-promoted, or a score rises without evidence. | High | Possible | Release gate; claim matrix; human sign-off; explicit exploratory label. | Project manager | Any new model or score change without linked evidence. | Organisational pressure; review at every gate. |

## R1 — Family-day confound

**Observed.** Train positives: 0. Validation positives: four DoS families. Test
positives: DDoS and PortScan. Validation/test overlap: empty. Wednesday's families are
sequential in time, so a time-ordered split is a family split.

**Response.**

1. Adopt this hard **coverage gate** for every future P2B split:

   - every evaluated positive family has at least one row in train, validation, and test;
   - the validation and test positive-family sets overlap;
   - the split generator writes the family × partition matrix into the artifact.

   The current data fails the gate for all six families. The gate is recorded in
   `p2b_protocol_analysis.json` under `coverage_gate`.

2. Do not transport a Wednesday DoS threshold to Friday DDoS/PortScan. A threshold is
   only valid for the families and conditions on which it was selected.

3. Prefer **A4** (external data with the tested families in train and validation).
   Allow **A1f** only as a preregistered cross-family zero-shot study.

**Owner:** Research lead. **Support:** data engineer (matrix), applied statistician
(estimand), ML evaluation engineer (reporting).

**Trigger:** any proposed split that fails the coverage gate is rejected before a fit.
**Residual:** coverage does not remove temporal drift, near-duplicate leakage, or
family imbalance. Report per-family counts and intervals.

## R2 — DDoS/PortScan zero-shot

**Observed.** DDoS (128,027) and PortScan (158,930) appear only in the test partition.
No DDoS or PortScan row exists in Monday–Tuesday or Wednesday.

**Response.**

1. Do not train per-family DDoS/PortScan heads. There is no labelled row to fit or
   validate.
2. Label every DDoS/PortScan table **“zero-shot; no validation threshold”**.
3. Report exact TP/FP counts and Clopper–Pearson upper bounds. Do not rank methods on
   zero-shot point estimates.
4. If a global threshold selected on Wednesday DoS out-of-fold scores is applied to
   Friday, state the transport assumption explicitly and treat the result as
   descriptive.
5. Acquire external DDoS/PortScan data before making a validated claim (A4).

**Owner:** ML evaluation engineer. **Support:** ML researcher, applied statistician.
**Trigger:** any doc, slide, or UI string that implies validated DDoS/PortScan
detection. **Residual:** zero-shot results may be weak or uninformative; that is a
valid negative result.

## R3 — Inspected test partition

**Observed.** Thursday–Friday is the development test partition. It has already been
used in P1, P2A, and the serving-model evaluation.

**Response.**

1. Rename the role in every new artifact: **development test**, not confirmatory test.
2. Adopt a **one-touch rule**: freeze the protocol, run the test once, and record the
   run hash, seed set, and code revision. No test-driven iteration.
3. Keep a test-access log. Any test access without a frozen protocol invalidates that
   run and must be documented.
4. Plan an external confirmatory set: CIC-IDS-2018 or UNSW-NB15 (P3), or a real
   labelled capture (P4). Do not call the current test blind.

**Owner:** Evaluation engineer. **Support:** research operations lead (external data),
reproducibility engineer (log). **Trigger:** test access without a frozen protocol.
**Residual:** no blind test exists until external data or capture is acquired.

## R4 — Sparse alerts and wide intervals

**Observed.** The P2A rules produced 1 TP at 10 alerts/10k and 33 TP at 100 alerts/10k
on 286,957 test positives. Per-family counts at those budgets are tiny.

**Response.**

1. Adopt a **minimum-reportable-count rule**: if a family has fewer than 10 alerts at a
   budget, report the count and an exact upper bound, not a recall estimate.
2. Report raw TP/FP/FN/TN alongside rates. Use Wilson intervals for recall/FPR,
   Clopper–Pearson for zero events, and the stratified bootstrap for PPV and alert
   volume.
3. Run a precision calculation before the experiment. If the expected interval is too
   wide to answer the question, say so before fitting.
4. Do not pool families unless the pooling rule is prespecified and justified.
5. Use Holm–Bonferroni across families and budgets, and report McNemar discordant
   counts, not only p-values.
6. Do not rank methods on point estimates alone; report intervals and paired counts.

**Owner:** Applied statistician. **Support:** ML evaluation engineer.
**Trigger:** fewer than 10 alerts for a family at a budget. **Residual:** low power at
10/10k is inherent; only more alerts or more data fix it.

## R5 — Missing external inputs

**Observed.** No PCAP/PCAPNG files, no CIC-IDS-2018 or UNSW-NB15 data, no real labelled
capture, no pilot partner, and no commissioned penetration test.

**Response.** Maintain a dependency register with entry criteria:

| Dependency | Entry criterion | Owner | Blocks |
| --- | --- | --- | --- |
| Tier B fan-out | PCAP/PCAPNG or a stateful 60-second aggregator with eviction; schema mapped to `unique_dst_ports_60s`, `unique_dst_hosts_60s`, `connection_attempts_60s`, `fanout_ratio_60s` | Packet/network engineer | Scan-detection claim; P2A Tier B |
| External datasets | Licence, provenance, Tier A schema mapping, and a positive-family coverage check. First pass: [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md) — UNSW-NB15 passes coverage for DoS/Reconnaissance with 8/12 Tier A features; the complete CIC-IDS-2018 set covers DoS/DDoS but has no PortScan, and its temporal split fails. | Research operations lead | P3; A4 |
| Real capture | Lab/testbed capture, CICFlowMeter parity, labelled flows, ethics/consent | Packet/network engineer; data-protection engineer | P4 |
| Pilot | Design partner, consent, ethics approval, prospective protocol | Research operations lead; product engineer | P8 |
| Pen test | Commissioned external test and report | Security platform engineer; SRE | P7 |

No synthetic or approximated substitute is allowed for any of these. If a dependency
is missing, the phase stays **blocked** and the gap is recorded.

**Trigger:** phase entry criteria not met. **Residual:** schedule and cost risk;
external actors control delivery.

## R6 — Claim and score drift

**Observed.** Detection is 4/10, production SaaS is 3/10, and overall is 4.5/10. No P2B
model exists. The risk is that a future exploratory result is promoted to a validated
claim, or that the scores rise without evidence.

**Response.**

1. Add a **release gate**: any new model artifact, registry row, UI claim, or score
   change must link the coverage gate, the claim-evidence matrix, and a human sign-off.
2. Reject a release if the coverage gate fails, if the test partition was used for
   tuning, or if the claim matrix lacks a SUPPORTED row.
3. Label exploratory results as **exploratory** in the title, abstract, tables, UI, and
   API metadata. Do not let the label decay.
4. Keep the scope ribbon and the 4/10 score until the evidence changes.
5. Review the register at every phase gate and after any new dataset arrives.

**Owner:** Project manager. **Support:** product engineer, technical writer, UX writer.
**Trigger:** any new model or score change without linked evidence. **Residual:**
organisational pressure; the gate is only as strong as its enforcement.

## Immediate actions

| Action | Owner | Artifact | Status |
| --- | --- | --- | --- |
| Freeze the coverage gate in the P2B preregistration template. | Research lead | `docs/P2B_PROTOCOL_ANALYSIS.md`; `p2b_protocol_analysis.json` | recorded |
| Record the disposition of residuals that controls do not remove. | Project owner; research lead | `docs/P2B_RESIDUAL_RISK_ACCEPTANCE.md` | recorded; sign-off pending |
| Add the zero-shot label rule to the evaluation protocol. | ML evaluation engineer | this register; future P2B protocol | proposed |
| Create the test-access log template. | Evaluation engineer | future `docs/TEST_ACCESS_LOG.md` | proposed |
| Write the A4 data requirements spec. | Research operations lead | future `docs/A4_DATA_REQUIREMENTS.md` | proposed |
| Write the Tier B capture/aggregator spec. | Packet/network engineer | future `docs/TIER_B_REQUIREMENTS.md` | proposed |
| Add the minimum-reportable-count rule. | Applied statistician | future protocol update | proposed |
| Add the release-gate check. | Project manager; test automation engineer | future CI/doc check | proposed |

The coverage gate and the residual-acceptance record are recorded now. The rest are
proposed controls for the next phase gate; none is executed by this audit.

## What does not change

- Serving artifact and threshold: unchanged.
- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.
- Scope: volumetric/scanning only; no blocking, botnet, web-attack, infiltration,
  zero-day, general NIDS, or production-readiness claim.
- Tier B fan-out remains unavailable.

## Reproduction

```bash
venv/Scripts/python.exe scripts/p2b_protocol_analysis.py \
  --output docs/p2b_protocol_analysis.json
venv/Scripts/python.exe -m pytest tests/test_p2b_protocol_analysis.py -q
```
