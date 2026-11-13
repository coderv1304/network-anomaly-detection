# P2B Protocol Analysis

**Status:** **BLOCKED** — the preregistered split cannot identify the requested supervised comparison.
**Date:** 2026-11-13.
**Scope:** flow-based volumetric and scanning behavior. Not a general NIDS.
**Evidence:** [`p2b_protocol_analysis.json`](p2b_protocol_analysis.json).
**Risk register:** [`P2B_RISK_REGISTER.md`](P2B_RISK_REGISTER.md).
**Reproduction:** [`../scripts/p2b_protocol_analysis.py`](../scripts/p2b_protocol_analysis.py).
**Predecessor:** [`VOLUMETRIC_DETECTOR.md`](VOLUMETRIC_DETECTOR.md) (zero training positives).

This is the decision record for P2B. It explains why the team is not executing the
amendment that looked simplest — an early/late Wednesday holdout — and what would
have to be true before any supervised volumetric model is trained.

## Executive decision

**Do not execute A1 (early/late Wednesday holdout) as the primary P2B protocol.**

There are two independent blockers, not one:

1. The preregistered training days (Monday–Tuesday) contain **0** volumetric/scanning
   positives. A supervised LogReg or Random Forest has no positive class to fit.
2. Even if training moved to Wednesday, the data confounds **attack family with day
   and time**. Wednesday validation positives are the four DoS families; Friday test
   positives are DDoS and PortScan. The two sets are disjoint. Within Wednesday, each
   attack campaign occupies a separate time window, so a time-ordered split is also a
   family split.

The second blocker is the decisive one. It means a Wednesday-trained model cannot
select a DDoS or PortScan threshold on validation, and any Friday DDoS/PortScan
number is a **cross-family zero-shot** result, not a validated operating point.

**Preferred path:** acquire external volumetric/scanning data with positives in both
training and validation (A4). **Conditional exploratory path:** reframe the exercise
as a cross-family zero-shot study (A1f), preregister that estimand, and never call it
validated DDoS/PortScan detection. **No model is trained now.**

## 1. The question P2B was meant to answer

The prompt asks for a preregistered comparison of Tier A rules against LogReg, Random
Forest, and IsolationForest, with thresholds frozen on Wednesday at 10 and 100 alerts
per 10,000 flows, five seeds, Holm–Bonferroni across families and budgets, and McNemar
on identical flows.

That comparison requires three things:

- labelled positives in the training partition;
- a validation partition that represents the families being tested;
- a test partition that has not influenced thresholds or model selection.

CIC-IDS-2017's day split fails the first two.

## 2. Evidence

### 2.1 Partition × family matrix

Counts are from the frozen partitions in
[`rule_baselines.json`](rule_baselines.json) and [`VOLUMETRIC_MODEL.json`](VOLUMETRIC_MODEL.json).

| Partition | Primary rows | Primary positives | Positive families | BENIGN | Excluded |
| --- | ---: | ---: | --- | ---: | ---: |
| Train (Mon–Tue) | 961,954 | **0** | none | 961,954 | 13,835 FTP/SSH patators |
| Validation (Wed) | 692,675 | 252,660 | DoS GoldenEye, DoS Hulk, DoS Slowhttptest, DoS slowloris | 440,015 | 11 Heartbleed |
| Test (Thu–Fri) | 1,157,883 | 286,957 | **DDoS, PortScan** | 870,926 | 4,182 Bot/Web/Infiltration |

`validation_test_overlap = []`. The validation and test positive families are
disjoint. A threshold selected on Wednesday DoS traffic is applied zero-shot to
Friday DDoS and PortScan traffic.

### 2.2 Wednesday is a sequence of campaigns

The frozen Wednesday partition has 692,686 rows; the raw file has 692,703. The extra
17 rows are duplicates removed by the frozen loader. The primary families do not
overlap in time:

| Family | Rows | First timestamp | Last timestamp |
| --- | ---: | --- | --- |
| DoS slowloris | 5,796 | 2017-07-05 02:24 | 2017-07-05 10:11 |
| DoS Slowhttptest | 5,499 | 2017-07-05 10:15 | 2017-07-05 10:37 |
| DoS Hulk | 231,072 | 2017-07-05 10:43 | 2017-07-05 11:07 |
| DoS GoldenEye | 10,293 | 2017-07-05 11:10 | 2017-07-05 11:19 |

A time-ordered boundary is therefore a family boundary. This is not a sampling
nuisance that more data would fix; it is how the capture was generated.

### 2.3 A 50/50 time split is a family split

Stable sort by `Timestamp`, first half train, second half validation, cut at
2017-07-05 10:35:

| Side | Rows | Primary positives | Families |
| --- | ---: | ---: | --- |
| Train | 346,343 | 11,167 | DoS Slowhttptest, DoS slowloris |
| Validation | 346,343 | 241,493 | DoS GoldenEye, DoS Hulk, DoS Slowhttptest (128 rows) |

Training never sees Hulk or GoldenEye. Validation never sees slowloris. The model
would be trained on two families and evaluated on two different families, then tested
on DDoS/PortScan. Calling that "validation" would hide the family shift.

### 2.4 The prescribed 3-fold expanding-window CV is degenerate

Contiguous time folds by row count:

| Fold | Rows | Primary positives | Families |
| --- | ---: | ---: | --- |
| 1 | 230,895 | **5** | DoS slowloris (5 rows) |
| 2 | 230,895 | 109,788 | DoS Hulk, DoS Slowhttptest, DoS slowloris |
| 3 | 230,896 | 142,867 | DoS GoldenEye, DoS Hulk |

Fold 1 has five positives. It cannot train or calibrate a supervised model, and it
cannot supply a stable threshold. Fold 2 adds three families; fold 3 drops slowloris
and Slowhttptest and adds GoldenEye. The CV is not a representative resampling of the
target; it is a walk through the campaign schedule.

## 3. Why A1 as proposed fails

A1 would train on the early Wednesday window and validate on the late window. The
audit shows the consequences:

- Training families: slowloris and Slowhttptest (plus 11 excluded Heartbleed rows).
- Validation families: Hulk and GoldenEye, with 128 stray Slowhttptest rows.
- DDoS and PortScan: absent from both, so no threshold and no per-family head.
- The first expanding-window fold has five positives, so the prescribed 3-fold CV
  collapses before it starts.

A1 is not a weaker version of P2B. It answers a different question: "does a model
trained on two DoS families transfer to two other DoS families and then to
DDoS/PortScan?" That is a legitimate zero-shot transfer study. It is not the
preregistered comparison, and it must not be reported as validated per-family
detection.

## 4. Options

| ID | Option | Verdict | Why |
| --- | --- | --- | --- |
| A1 | Early/late Wednesday holdout | **Rejected as primary** | Trains on slowloris/Slowhttptest, validates on Hulk/GoldenEye; DDoS/PortScan still absent from train and validation. |
| A1f | Wednesday expanding-window CV with out-of-fold thresholds, Friday test | **Exploratory only** | Uses all Wednesday rows and freezes OOF thresholds, but the test families are unseen and fold 1 is degenerate. Must be labelled cross-family zero-shot. |
| A2 | Unsupervised IsolationForest on Monday–Tuesday | **Fallback only** | Needs no positives, but cannot answer rules-vs-supervised and its Friday metrics are also zero-shot. |
| A3 | Move Wednesday into training | **Rejected** | Removes the validation partition and still leaves DDoS/PortScan test-only. |
| A4 | External volumetric/scanning data | **Preferred** | The only option that can put the tested families in train and validation. Requires data, licensing, and human approval. |

A1f, if approved, needs its own preregistration:

- estimand: cross-family zero-shot transfer from Wednesday DoS to Friday DDoS/PortScan;
- expanding-window CV inside Wednesday, with a minimum-positive guard for fold 1;
- thresholds frozen on out-of-fold Wednesday scores at 10 and 100 alerts/10k;
- one test pass, no retuning;
- per-family recall with CIs, explicitly labelled zero-shot;
- no claim of validated DDoS/PortScan detection.

### 4.1 Coverage gate

Every future P2B split must pass a hard family-coverage gate before any fit:

1. every evaluated positive family has at least one row in train, validation, and test;
2. the validation and test positive-family sets overlap;
3. the split generator writes the family × partition matrix into the artifact.

The current data fails the gate for all six families. The machine-readable result is
`coverage_gate` in [`p2b_protocol_analysis.json`](p2b_protocol_analysis.json). The gate
is a feasibility check, not a power check; the minimum-reportable-count rule in the
[`P2B_RISK_REGISTER.md`](P2B_RISK_REGISTER.md) handles statistical precision.

## 5. Team review

| Role | Assessment | Condition or action |
| --- | --- | --- |
| Research lead | The estimand is unidentified under the frozen split. Validation/test family disjointness is fatal to a transported threshold. | Do not approve A1 as primary. Escalate A4. |
| Technical writer | The words "validated", "detects DDoS", and "detects PortScan" would be false under A1/A1f. | Use "cross-family zero-shot" in titles, tables, and captions if A1f runs. |
| Backend engineer | No backend change is needed to record the blocker. A future model needs a new registry row, not an edit to the serving row. | Keep the serving path frozen; validate registry isolation when a new artifact exists. |
| UX writer | No UI copy should imply validated volumetric detection or a new score. | Keep the scope ribbon and the 4/10 label. |
| ML evaluation engineer | At 10 alerts/10k the per-family alert counts are tiny; CIs will be wide. McNemar needs discordant counts, not just a p-value. | Predefine the comparison table and the minimum reportable counts. |
| Applied statistician | Family is confounded with day and time; fold 1 has 5 positives; Wednesday DoS thresholds do not transport to Friday DDoS/PortScan. | Require A4 or an explicit zero-shot estimand. Do not call A1 a validation split. |
| Detection engineer | Per-flow Tier A cannot represent 60-second fan-out; Tier B is unavailable. PortScan is the weakest case for a per-flow model. | Report per-family zero-shot recall; do not claim scan coverage. |
| Measurement scientist | Benchmark prevalence 24.78% is a dataset property; PPV at 0.01/0.1/1% must be computed from test TPR/FPR. | Keep prevalence labels explicit; no site-prevalence claim. |
| ML researcher | The fixed grid is reasonable, but no supervised fit is possible on Monday–Tuesday. A1 would train on two families only. | Reject A1 as primary; if A1f, freeze the protocol before fitting. |
| Evaluation engineer | Thresholds must be label-blind and frozen before the test load. Bootstrap intervals must respect flow non-independence. | Reuse the P1/P2A interval and bootstrap conventions; no test-label access. |
| Data engineer | Wednesday timestamps parse cleanly; 17 duplicates are removed; families are sequential. The family-day matrix is reproducible. | Publish the coverage matrix with any future split. |
| Reproducibility engineer | The audit is deterministic and hash-pinned; the serving hash is unchanged. | Re-run the generator twice and compare hashes before publishing. |
| Packet/network engineer | There are no PCAP/PCAPNG files. `Timestamp` is a flow start time, not a packet time. | Tier B fan-out remains unavailable; do not approximate it. |
| Test automation engineer | The split boundary, OOF threshold freezing, metric computation, and registry isolation need unit tests. | Add tests before any training code is merged. |
| SRE | A 5-seed × grid run is an offline batch job; it must not share the serving process. | Estimate runtime and memory before approval; no production rollout. |
| Performance engineer | RF on roughly 230k rows × 12 features across 60 fits is hours, not minutes, and may exceed workstation memory if partitions are copied. | Prototype one fit and measure before committing to the full grid. |
| Integrations engineer | P6 depends on P2B; no integration should consume an unvalidated model. | Keep integrations unchanged until a model is approved. |
| Product engineer | A new model claim would change the product claim; the current scores are 4/10 detection and 3/10 SaaS. | Do not ship a new detector claim from A1f. |
| Security platform engineer | No blocking, containment, or production-readiness claim is supported. | Keep response previews and scope text unchanged. |
| Operations lead | Alert volume at 10/10k is low, but precision is poor; tuning on-call to an unvalidated model would be misleading. | No runbook or on-call change. |
| Research operations lead | CIC-IDS-2017 is public research data; external datasets need licences and provenance records. | Record licence and source for A4. |
| Data-protection engineer | Flow CSVs can contain IP addresses; publish aggregates, not raw rows. A real capture needs ethics, consent, and retention rules. | No raw-flow publication; review A4 before acquisition. |

## 6. Decision and conditions

**P2B remains BLOCKED.** The blocker is the combination of zero training positives
and the family-day confound. The audit is the deliverable; no model, registry row, or
new claim is created.

Conditions for reopening P2B:

1. **A4 (preferred):** acquire volumetric/scanning data with labelled positives in
   both train and validation, and at least one positive family shared with the test
   partition. Confirm the licence, provenance, and Tier A schema mapping. The first
   acquisition pass is recorded in
   [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md): UNSW-NB15 passes a
   leakage-safe coverage gate for DoS/Reconnaissance but lacks 4 Tier A features.
   The complete CIC-IDS-2018 set has DoS and DDoS across several days but no
   PortScan; its temporal split fails because the positives sit in early days, and
   its group split covers DoS/DDoS only. Neither dataset closes A4 for a claim that
   includes PortScan.
2. **A1f (exploratory):** obtain explicit human approval for a cross-family zero-shot
   study, preregister the estimand and the fold guard, and accept that DDoS/PortScan
   are test-only.
3. **A2 (fallback):** if only an unsupervised baseline is approved, report it as an
   anomaly baseline, not as the P2B comparison.

Acceptance criteria for any future run:

- one table answers: at 10 alerts/10k, which method catches the most DDoS and
  PortScan with the lowest FPR;
- all thresholds and seeds are logged;
- no test-label tuning;
- per-family recall, FPR, PPV at 0.01/0.1/1%, alerts/10k, bootstrap CIs, ECE/Brier,
  Holm-adjusted comparisons, and McNemar discordant counts are reported;
- the serving artifact and its registry row are untouched.

## 7. What does not change

- Serving artifact: `models/model_bundle_rf_day_based_seed42.pkl`,
  SHA-256 `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`.
- Serving threshold: `0.002515048908954043`; calibration: `uncalibrated`.
- Detection score: **4/10**. Production SaaS: **3/10**. Overall: **4.5/10**.
- Scope: volumetric/scanning only. Botnet, web attacks, infiltration, zero-day,
  general NIDS, blocking, and production readiness remain out of scope.
- Tier B fan-out remains unavailable; no raw packets exist.

## 8. Next steps

1. Human decides between A4 (preferred) and A1f (exploratory).
2. If A4: acquire data and licence, map to Tier A, and rerun the coverage audit before
   training.
3. If A1f: write the amendment preregistration, add the fold guard and OOF threshold
   tests, and freeze the protocol before the first fit.
4. Do not train on test labels, relabel patators as volumetric, or synthesise
   positives to unblock the run.

## 9. Reproduction

```bash
venv/Scripts/python.exe scripts/p2b_protocol_analysis.py \
  --output docs/p2b_protocol_analysis.json
venv/Scripts/python.exe -m pytest tests/test_p2b_protocol_analysis.py -q
```

The JSON records the family-day matrix, Wednesday time profile, half-split counts,
expanding-fold counts, findings, options, and artifact hashes.
