# Volumetric Detector (Phase P2B)

**Status:** BLOCKED. **Scope:** flow-based volumetric and scanning behavior; not a general NIDS.

**Artifact:** [`VOLUMETRIC_MODEL.json`](VOLUMETRIC_MODEL.json). **Audit script:** [`../scripts/volumetric_model.py`](../scripts/volumetric_model.py). **Baselines:** [`RULE_BASELINES.md`](RULE_BASELINES.md).

This document answers the P2B question: can the preregistered split support the rules-versus-supervised comparison? It does not report model metrics, because the audit found that the training partition cannot fit a supervised positive class.

## Protocol as written

| Item | Value |
| --- | --- |
| Train days | Monday, Tuesday |
| Validation days | Wednesday |
| Test days | Thursday, Friday |
| Seeds | 42, 43, 44, 45, 46 |
| Budgets | 10, 100 alerts / 10k |
| Threshold partition | Wednesday only |

## Partition audit

| Partition | Days | Rows after dedup | Primary rows | Positives | Negatives | Excluded | Benchmark prevalence |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Train | Monday, Tuesday | 975,789 | 961,954 | 0 | 961,954 | 13,835 | 0.00% |
| Validation | Wednesday | 692,686 | 692,675 | 252,660 | 440,015 | 11 | 36.48% |
| Test | Thursday, Friday | 1,162,065 | 1,157,883 | 286,957 | 870,926 | 4,182 | 24.78% |

Training label counts after dedup: `BENIGN` 961,954, `FTP-Patator` 7,938, `SSH-Patator` 5,897.

The raw training files contain 975,827 rows; the frozen loader removes 38 cross-file duplicates, leaving 975,789.

The only non-benign training labels are the two credential-attack families, which the P2A policy excludes. There is no volumetric or scanning positive in the training partition.

## Blocker

**`training_partition_has_no_target_positives`**: The frozen Monday-Tuesday training partition contains 0 volumetric/scanning positives across 961,954 primary rows. The only non-benign training labels are FTP-Patator and SSH-Patator, which the P2A label policy excludes. A supervised binary head cannot be fitted, so no LogReg or Random Forest comparison is possible under the preregistered split.

This is a split-design problem, not a code defect. Training on test labels, relabelling patators as volumetric, or synthesising positives would each break the label policy or the integrity contract. None were done.

## Feasibility

| Model family | Trainable under the preregistered split |
| --- | --- |
| Logistic Regression | no |
| Random Forest | no |
| Isolation Forest | yes |
| Full P2B comparison | no |

The training partition contains zero volumetric/scanning positives. A supervised binary head has no positive class to fit. Only the unsupervised Isolation Forest is trainable, and it cannot satisfy the full rules-vs-supervised comparison.

## Amendments requiring human approval

| ID | Amendment | Change | Pros | Cons | Recommended |
| --- | --- | --- | --- | --- | --- |
| A1 | Time-ordered holdout inside Wednesday | Train on the earlier portion of Wednesday, select thresholds on the later portion, keep Thursday-Friday as the test partition. | Creates training positives while preserving a held-out test day range. | Wednesday is currently the validation partition; the amendment reduces validation size and changes the preregistered split. | yes, if the supervised comparison is required |
| A2 | Unsupervised-only P2B | Train Isolation Forest on Monday-Tuesday benign traffic and freeze thresholds on Wednesday. Do not report LogReg/RF. | Uses the existing split unchanged and needs no new labels. | Cannot answer the pack's rules-vs-supervised question and leaves the main model comparison unexecuted. | no, unless the supervised comparison is out of scope |
| A3 | Move volumetric days into training | Train on Monday-Wednesday and test on Thursday-Friday. | Adds the DoS families to training. | Removes the independent validation partition and makes threshold selection and test reporting depend on the same days. | no |
| A4 | External volumetric capture | Acquire a labelled capture with volumetric/scanning traffic and use it as an additional training or validation source. | Adds independent positives and supports cross-dataset claims. | Requires data, licensing, and capture effort that do not exist yet. | yes, as the longer-term fix |

The audit does not execute an amendment. P2B's human gate requires approval of a new artifact, and changing the split changes every downstream claim.

Isolation Forest is technically trainable on the existing split, but it cannot answer the pack's rules-versus-supervised question on its own. It was not run as a partial substitute, because a one-model result would be easy to misread as the P2B comparison.

## What was not executed

- No Logistic Regression, Random Forest, Gradient Boosting, or Isolation Forest model was trained.
- No model artifact or registry row was created.
- No recall, FPR, PPV, calibration, or McNemar result is reported.
- The serving artifact and its threshold are unchanged.

## Decision

**Rules remain the only evaluated Tier A baseline.** The P2B supervised comparison is blocked until a split with training positives is approved. The broader family-day confound is analyzed in [`P2B_PROTOCOL_ANALYSIS.md`](P2B_PROTOCOL_ANALYSIS.md). Detection remains **4/10** and no product claim changes.

## Reproduction

```bash
venv/Scripts/python.exe scripts/volumetric_model.py \
  --output docs/VOLUMETRIC_MODEL.json \
  --report docs/VOLUMETRIC_DETECTOR.md
```

