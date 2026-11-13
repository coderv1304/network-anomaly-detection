# P2B Residual Risk Acceptance

**Status:** **proposed acceptance for the blocked phase; not accepted for release.**
**Date:** 2026-11-13.
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Related:** [`P2B_RISK_REGISTER.md`](P2B_RISK_REGISTER.md), [`P2B_PROTOCOL_ANALYSIS.md`](P2B_PROTOCOL_ANALYSIS.md), [`p2b_protocol_analysis.json`](p2b_protocol_analysis.json).
**Sign-off:** project owner and research lead — **pending named approval**.

This record answers the question the risk register cannot answer by itself: **what
happens to the risks that controls do not remove?** The answer is not “they are
solved.” It is a disposition: close, reduce, or accept, with the scope of acceptance
and the condition that would reopen it.

The acceptance applies **only to the current blocked phase**, where no model, no
registry row, and no detection claim exist. It does **not** authorise a release, a
score change, or a “validated volumetric detector” claim.

## 1. Disposition

| Risk | Residual after controls | Disposition now | Closure condition | Reopens when |
| --- | --- | --- | --- | --- |
| **R1** Validation not representative | The data gap remains; the coverage gate only prevents misuse. | **Accept for blocked phase; do not model.** | External data with every evaluated family in train and validation. | A proposed split passes the coverage gate. |
| **R2** DDoS/PortScan zero-shot | No validation rows exist; labels and upper bounds do not create validation. | **Accept only as a zero-shot descriptor; never as validated detection.** | Labelled DDoS/PortScan rows in train and validation. | A4 data arrives, or a human approves a scoped zero-shot study. |
| **R3** Non-blind test | The existing test partition cannot become blind. | **Accept as development evidence only.** | External confirmatory set not used in development. | An external dataset or capture is acquired and frozen. |
| **R4** Low power at 10/100 per 10k | Intervals remain wide; the reporting rule labels, but does not remove, uncertainty. | **Accept and quantify; report “insufficient evidence” where required.** | Not fully closeable at these budgets; reduce by raising the budget or acquiring more data. | A budget or data volume supports the required precision. |
| **R5** Missing external inputs | Tier B, datasets, capture, pilot, and pen test are still absent. | **Accept as blocked dependencies; no substitutes.** | Each dependency meets its entry criterion. | A dependency is delivered and verified. |
| **R6** Claim/score drift | Governance risk never reaches zero. | **Accept with release gate and review cadence.** | Ongoing control, not a one-time closure. | Every release and every phase gate. |

## 2. Quantified low-power residual (R4)

The following numbers are from the frozen `rate_bytes` rule in
[`rule_baselines.json`](rule_baselines.json), not from a P2B model. They show the
precision problem that any future model will inherit at these budgets.

| Budget | Family | Test support | Alerts | Recall | 95% interval | Reading |
| --- | --- | ---: | ---: | ---: | --- | --- |
| 10 / 10k | DDoS | 128,027 | 1 | 0.00078% | 0.00014%–0.00442% | One alert; the interval spans roughly 32×. |
| 10 / 10k | PortScan | 158,930 | 0 | 0% | 0–0.00242% | No alert; only an upper bound. |
| 100 / 10k | DDoS | 128,027 | 33 | 0.0258% | 0.0184%–0.0362% | 33 alerts; the interval still spans roughly 2×. |
| 100 / 10k | PortScan | 158,930 | 0 | 0% | 0–0.00242% | No alert; only an upper bound. |

**Consequence:** at 10 and 100 alerts per 10,000 flows, a per-family recall point
estimate is not an adequate answer on its own. Report the raw count, the interval, and
the alert budget. If the count is below the minimum-reportable threshold, write
“insufficient evidence,” not a recall estimate.

## 3. Stop rules

These are hard rules, not guidelines:

1. **No validated DDoS/PortScan claim** until both families have labelled rows in
   train and validation and a threshold frozen on validation.
2. **No “blind” or “confirmatory” claim** for Thursday–Friday. Call it the development
   test. Only an external set not used in development can be confirmatory.
3. **No per-family recall claim** when a family has fewer than 10 alerts at a budget.
   Report the count and an exact upper bound.
4. **No scan-detection claim** without Tier B fan-out from raw packets or a documented
   stateful 60-second aggregator.
5. **No score increase** without a SUPPORTED claim-evidence row and a human sign-off.
6. **No model artifact or registry row** without a passing coverage gate.

## 4. What “accept” means here

Accepting a residual for the blocked phase means:

- the gap is recorded, owned, and reviewed;
- the permitted language is explicit;
- no downstream claim relies on the missing evidence;
- the phase stays **blocked** until the closure condition is met.

It does **not** mean:

- the risk is gone;
- the number is validated;
- the detector is ready;
- the 4/10 score can rise.

## 5. Sign-off and review

| Role | Disposition | Named sign-off | Date |
| --- | --- | --- | --- |
| Project owner | Accept for blocked phase; not for release | pending | — |
| Research lead | Accept R1/R2 only as zero-shot; prefer A4 | pending | — |
| Applied statistician | Accept R4 with minimum-reportable-count rule | pending | — |
| Evaluation engineer | Accept R3 as development evidence only | pending | — |
| Research operations lead | Accept R5 as blocked dependencies | pending | — |
| Project manager | Maintain R6 release gate | pending | — |

**Review cadence:** before any P2B fit, on arrival of A4 data, on Tier B delivery,
before any release, and quarterly while the phase is blocked.

## 6. Reopening conditions

P2B can leave the blocked state only when one of these is true:

1. **A4 data** provides every evaluated positive family in train and validation, with
   a licence and Tier A schema mapping, and the coverage gate passes. The first
   acquisition pass is in [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md):
   UNSW-NB15 passes coverage for DoS/Reconnaissance after group deduplication, but
   only 8/12 Tier A features are available; the complete CIC-IDS-2018 set covers
   DoS/DDoS but has no PortScan, and its temporal split fails. A4 is **not** closed.
2. **A1f** is explicitly approved as a cross-family zero-shot study, with a frozen
   estimand, a fold guard, and the R1/R2 residuals scoped in the title and every
   table.

R3 remains open until an external confirmatory set exists. R4 remains open at
10/100 per 10k by construction; it can be reduced only by more alerts or more data.
R5 closes dependency by dependency. R6 is never closed; it is reviewed.

## 7. What does not change

- Serving artifact and threshold: unchanged. SHA-256
  `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`.
- Detection **4/10**, SaaS **3/10**, overall **4.5/10**.
- Scope: volumetric/scanning only. No botnet, web-attack, infiltration, zero-day,
  general NIDS, blocking, or production-readiness claim.
- Tier B fan-out remains unavailable.

## 8. Reproduction

```bash
venv/Scripts/python.exe scripts/p2b_protocol_analysis.py \
  --output docs/p2b_protocol_analysis.json
venv/Scripts/python.exe -m pytest tests/test_p2b_protocol_analysis.py -q
```

The low-power table is transcribed from
[`rule_baselines.json`](rule_baselines.json) under
`rules.rate_bytes.test.{10,100}.per_family_recall`.
