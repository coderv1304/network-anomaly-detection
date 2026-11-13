# D9 — Cost-Sensitive Evaluation and Detection Release Gate

**Status:** **complete; release gate FAIL.** The detector has a narrow cost-justified operating region. Serving, evaluation, and gating now use the same Random Forest seed 42 artifact, but the detector does not meet the false-positive, alert-rate, Bot-recall, or calibration gates, and has no external or pilot evidence. **No 9/10 detection claim is allowed. Detection remains 4/10.**
**Date:** 2026-11-11.
**Machine-readable result:** [`COST_SENSITIVE_RESULTS.json`](COST_SENSITIVE_RESULTS.json).
**Script:** `scripts/cost_sensitive_eval.py`.
**Score-cache builder:** `scripts/build_score_cache.py`.
**Related:** [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md), [`UNSEEN_FAMILY_AND_BOTNET.md`](UNSEEN_FAMILY_AND_BOTNET.md), [`D8_PROSPECTIVE_PILOT_PROTOCOL.md`](D8_PROSPECTIVE_PILOT_PROTOCOL.md), [`S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md`](S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md).

## 1. Why a cost model is required

A detector is not useful or useless in the abstract. It is useful when the cost of the false positives it creates, plus the cost of the attacks it misses, is lower than the cost of the alternative. This report makes that comparison explicit.

**No organization has supplied its real costs.** The results are therefore a **sensitivity curve over the cost ratio**, not a dollar claim. The report never invents an analyst salary or a breach cost.

| Symbol | Meaning in this report |
| --- | --- |
| `C_FP` | Cost of one analyst review of one alert. All alerts — true or false — consume review time under the threshold policy. Normalised to 1. |
| `C_FN` | Cost of one missed attack. |
| `r` | `C_FN / C_FP`. Reported over `{1, 2, 3, 5, 10, 30, 100, 300, 1000}`. |
| Review time | 5 analyst minutes per alert is an **illustrative planning assumption**, not a measured value. The D8/S7 pilot is designed to measure it. |
| Flow base | 1,162,065 deduplicated Thursday+Friday flows; 291,139 attacks; 870,926 benign. |

> **Prevalence caveat (added by P1).** Every break-even ratio in this report is computed at the test partition's benchmark prevalence of **25.05%**. It is not prevalence-free. At 0.1% prevalence, the served RF's five-seed break-even is about **72.47** under the all-alerts-reviewed model, not 1.21. See [`PREVALENCE_EVAL.md`](PREVALENCE_EVAL.md) for the full grid and confidence intervals.

Expected cost per 10,000 flows:

```text
cost_detector(r) = (alerts + r * false_negatives) * 10,000 / n_flows
cost_none(r)     = r * attacks * 10,000 / n_flows
```

The detector beats doing nothing only when:

```text
r > alerts / true_positives = 1 / precision
```

That ratio is the **break-even cost ratio**. It is the single most useful number in this report: if one missed attack is worth less than that multiple of one analyst review, the detector destroys value even before engineering and support costs.

## 2. Artifacts evaluated

| Key | Artifact | Role |
| --- | --- | --- |
| `lr` | Three-class Logistic Regression, threshold `0.13454342680553322`, seed 42 | Legacy comparison; no longer served |
| `rf` | Day-based Random Forest, seeds 42–46; seed 42 is the registry-active serving artifact | **Current served model and evaluated artifact** |
| `if` | Benign-only Isolation Forest, seeds 42–46 | Anomaly baseline |

Thresholds were selected on Wednesday validation at ≤1% FPR and applied unchanged to Thursday+Friday. No threshold, policy, or model was chosen using test labels.

**Artifact identity now passes.** The registry-active serving version `serving-rf-day-based-seed42-v1` has SHA-256 `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`, the same hash recorded in `models/model_manifest_rf_day_based_seed42.json`. The D9 gate compares hashes rather than names. The serving entry is explicitly `calibration_version=uncalibrated` because the available isotonic artifact has held-out ECE ≈0.208 and fails the 0.05 gate; the console therefore shows no confidence percentage.

## 3. Expected cost at the frozen threshold

Mean over the available seeds (LR: one artifact; RF and IF: five seeds). `Cost @ r=10` and `Cost @ r=100` are per 10,000 flows, in units of `C_FP`.

| Model | Test FPR | Recall | Precision | Alert rate | Alerts / 10k | Review h / 10k | Break-even `r` | Cost @ r=10 | Cost @ r=100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LR (legacy)** | 2.66% | 3.52% | 0.3065 | 2.88% | 288 | 24.0 | **3.26** | 24,459 | 242,002 |
| **RF (served)** | 4.11% ± 3.27% | 58.30% ± 14.79% | 0.8367 | 17.68% | 1,768 | 147.4 | **1.21** (1.04–1.44) | 12,216 | 106,244 |
| **IF (anomaly)** | 1.16% | 0.46% | 0.087 | 0.99% | 99 | 8.2 | **unstable** (2.68–1,512) | 25,037 | 249,485 |
| No detector | — | 0% | — | 0% | 0 | 0 | — | 25,054 | 250,536 |

Reading the table:

- **LR (legacy comparison)** must be worth more than **3.26 analyst reviews per missed attack** before it beats doing nothing. At `r=10` it saves only about 594 cost units per 10,000 flows (2.4%) and still leaves 96.5% of attacks missed. It creates 288 alerts and 24 analyst hours per 10,000 flows.
- **RF (served)** breaks even at about **1.21** and saves 51% of cost at `r=10`. But it creates 1,768 alerts and 147 analyst hours per 10,000 flows. That is not a viable operating point for most teams.
- **IF** is not a useful detector. Its mean precision is 8.7%, and three of five seeds find almost no attacks at all. The tiny mean saving at `r=10` is an artefact of averaging seed-level curves with wildly different break-even ratios (2.68 to 1,512); it is not a stable operating result.
- None of these numbers includes engineering, support, storage, or the cost of the 186 unfixed base-image advisories. Those only make the detector's economics worse.

### 3.1 Cost curve at the frozen threshold

| `r` | LR detector | RF detector | IF detector | No detector | Best model |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1 | 2,705 | 2,813 | 2,593 | 2,505 | none (all destroy value) |
| 10 | 24,459 | **12,216** | 25,037 | 25,054 | RF |
| 100 | 242,002 | **106,244** | 249,485 | 250,536 | RF |
| 1,000 | 2,417,425 | **1,046,524** | 2,493,966 | 2,505,359 | RF |

RF is the best of the three models at every ratio above break-even. It is still not deployable: the served artifact is LR, and RF's alert volume is outside any declared budget.

## 4. Expected cost under a fixed alert budget

An alert budget changes the operating point. Instead of applying a frozen threshold, the model ranks flows and the team reviews a fixed number of alerts per 10,000 flows. This is closer to an operational queue.

### 4.1 Budget of 50 alerts per 10,000 flows

| Model | Alerts | True positives | False positives | Precision | Recall | Review h / 10k | Break-even `r` | Cost @ r=10 | Cost @ r=100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LR (legacy)** | 5,810 | 367 | 5,443 | 6.3% | 0.13% | 4.17 | **15.83** | 25,072 | 250,270 |
| **RF (served)** | 5,810 | 4,940 | 870 | 85.0% | 1.77% | 4.17 | **1.18** | 24,679 | 246,335 |
| **IF** | 5,810 | 213 | 5,597 | 3.7% | 0.07% | 4.17 | **1,910** | 25,085 | 250,403 |
| No detector | 0 | 0 | 0 | — | 0% | 0 | — | 25,054 | 250,536 |

At 50 alerts per 10,000 flows, the queue is cheap in analyst time (about 4.2 hours per 10,000 flows), but **LR's precision is only 6.3%**. Most of the budget is spent on benign flows. RF is far better ranked (85% precision) but still finds only 1.77% of attacks.

### 4.2 Budget of 100 alerts per 10,000 flows

| Model | Alerts | True positives | False positives | Precision | Recall | Review h / 10k | Break-even `r` | Cost @ r=10 | Cost @ r=100 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **LR (legacy)** | 11,621 | 2,359 | 9,262 | 20.3% | 0.81% | 8.33 | **4.93** | 24,951 | 248,606 |
| **RF (served)** | 11,621 | 10,495 | 1,126 | 90.3% | 3.61% | 8.33 | **1.11** | 24,250 | 241,604 |
| **IF** | 11,621 | 1,075 | 10,546 | 9.3% | 0.37% | 8.33 | **151.5** | 25,061 | 249,711 |
| No detector | 0 | 0 | 0 | — | 0% | 0 | — | 25,054 | 250,536 |

At 100 alerts per 10,000 flows:

- **RF** is genuinely cost-competitive: 90.3% precision, break-even `r≈1.11`, about 8,932 cost units saved per 10,000 flows at `r=100`.
- **LR (legacy)** needs `r>4.93`. It saves only 103 units at `r=10` and 1,930 at `r=100`. It spends 8.3 analyst hours per 10,000 flows to find 0.81% of attacks.
- **IF** is unusable: 9.3% precision and a break-even ratio of 151.5.

### 4.3 What the budget policy buys and what it gives up

The budget policy does not fix the model. It changes the trade-off:

- It caps analyst load at 4.2 or 8.3 hours per 10,000 flows, which is a real operational constraint the frozen threshold violates.
- It raises precision because the highest-ranked flows are reviewed first.
- It sharply lowers recall: RF finds 1.8% of attacks at 50 alerts/10k and 3.6% at 100 alerts/10k. The remaining 96–98% are missed.
- The cost saving is therefore concentrated in the small high-confidence slice. If the site's threat model requires catching a broad range of attacks, a high-precision, low-recall queue is not sufficient.

## 5. When the detector is useful

State these conditions explicitly; they are narrow.

1. **The site has a real cost ratio.** The site can state `C_FN/C_FP` and a review budget. For the served RF at the frozen threshold, usefulness requires `C_FN/C_FP > 1.21`; at a 100-alert budget, `>1.11`. If a missed attack is valued below that, the detector destroys value. The legacy LR needed `>3.26`/`>4.93`.
2. **The site accepts very low recall at a small queue.** The served RF catches 58.3% at its frozen threshold but at a 17.7% alert rate. At a 100-alert budget it catches 3.6%. The legacy LR catches 3.5% at its threshold and 0.8% at a 100-alert budget. There is no operating point with both high recall and a small queue.
3. **The alert budget is enforced.** The queue must cap alerts and record under-fill and unreviewed flows. A threshold that produces 1,768 alerts per 10,000 flows is not an operating policy.
4. **A human reviews every alert.** The current system must not block, quarantine, or auto-remediate. All cost calculations assume review; automatic action on a low-recall model would be harmful.
5. **The deployment uses a single frozen artifact whose identity is verified.** The registry-active serving artifact now has the same SHA-256 as the evaluated seed 42 manifest, and the startup/deployment gate refuses a mismatch.
6. **The scope is narrow.** The only supported use is prioritising a small number of flows for human triage on CIC-IDS-2017-like traffic. It is not a claim of botnet, zero-day, or broad intrusion detection.

## 6. When the detector is not useful

The detector is **not useful**, and must not be presented as useful, when:

- `C_FN/C_FP` is below the break-even ratio (1.21 for the served RF at threshold, 1.11 at a 100-alert budget; the legacy LR needed 3.26/4.93);
- the team cannot staff the review hours (147 h per 10,000 flows for the served RF at threshold);
- the requirement is to catch Bot or other unseen families (Bot recall is 0.94% for RF and far lower for the others; see [`UNSEEN_FAMILY_AND_BOTNET.md`](UNSEEN_FAMILY_AND_BOTNET.md));
- the site needs calibrated probabilities (ECE is 0.25 for RF and the serving entry is explicitly uncalibrated);
- the traffic is not from the CIC-IDS-2017 distribution (no external validation exists);
- the site needs multi-day threshold stability (test FPR ranges from 0.73% to 7.85% across RF seeds; see [`THRESHOLD_POLICY_V2.md`](THRESHOLD_POLICY_V2.md));
- the site needs automated response rather than human triage;
- the claim is "9/10 detection" or "enterprise-ready".

## 7. Release gate for a 9/10 detection claim

This gate is published before any 9/10 claim. It is machine-checked in `scripts/cost_sensitive_eval.py`; the current output is **FAIL** on seven of nine checks.

| Check | Requirement | Current observed | Status |
| --- | --- | --- | --- |
| Artifact identity | The served artifact is the artifact evaluated and gated | served RF hash matches evaluated seed 42 manifest | **PASS** |
| FPR every day and seed | Test FPR ≤ 1% on every day and every seed | max 7.85% | **FAIL** |
| Alert rate | ≤ 2% of flows at the frozen threshold | 17.68% mean | **FAIL** |
| Bot recall | ≥ 0.50 minimum (0.70 desired) at ≤1% FPR | min seed 0.05% | **FAIL** |
| Calibration | ECE ≤ 0.05 on held-out test | 0.25 | **FAIL** |
| External dataset | Same gate passes on at least one independent external dataset | blocked; no dataset | **FAIL** |
| Prospective pilot | D8/S7 human-review pilot completed with predeclared criteria | not run; no design partner | **FAIL** |
| Site cost model | Site-supplied `C_FP`, `C_FN`, and review budget | not supplied; ratio curve only | **FAIL** |
| Seeds | At least five estimator seeds for the exact served configuration | five RF seeds; served bytes are seed 42 | **PASS** |

**Verdict: FAIL. No 9/10 detection claim is allowed. Detection remains 4/10.**

### 7.1 Additional cost gate for a scoped usefulness claim

Even after the nine checks above, a scoped cost claim should require:

1. A **positive net benefit at the site's own cost ratio**, with a bootstrap interval that excludes zero.
2. The benefit must hold **on every test day**, not only in a pooled mean.
3. The review load must fit the site's declared analyst budget, measured in the pilot rather than assumed at 5 minutes per alert.
4. The result must be reproduced on the **exact served artifact**. This is now satisfied by SHA-256 identity between the registry-active artifact and the evaluated seed 42 manifest.
5. The evaluation must be re-run with the gate hash committed before the run. A gate written after seeing the result is not a gate.

## 8. Interpretation and honest conclusion

The cost analysis does not rescue the detection score.

- The **served RF** is a real, if narrow, cost-competitive ranker under a fixed alert budget. That is a genuine finding and is worth reporting.
- At the frozen threshold it creates a 17.7% alert rate; at a 100-alert budget it recovers only 3.6% of attacks. Neither is a broad detection claim.
- The **legacy LR** is much weaker: break-even `r≈3.26` at threshold and `≈4.93` at a 100-alert budget, with 0.8% recall at that budget.
- The **Isolation Forest** is not viable at any plausible cost ratio.
- None of the three has external validation, calibrated probabilities, stable multi-day FPR, or Bot recall.
- Artifact identity now passes, so the model with the best cost profile is what users actually run. That does not fix the alert-volume or unseen-family failures.

Therefore the correct statement is: **"The served random-forest baseline can be cost-competitive for a small, high-precision human-triage queue on this dataset, if missed attacks are valued at more than about 1.1 analyst reviews and the team can staff the queue. It still produces too many alerts at its frozen threshold, misses most attacks at a small budget, and has no external or pilot evidence. No claim of 9/10 detection, operational effectiveness, or SaaS readiness is supported."**

## 9. Reproduction

```bash
# Build the score caches used for the alert-budget policy (regenerable).
venv/Scripts/python.exe scripts/build_score_cache.py --model lr --seeds 42
venv/Scripts/python.exe scripts/build_score_cache.py --model if --seeds 42,43,44,45,46

# Run the cost-sensitive evaluation and release gate.
venv/Scripts/python.exe scripts/cost_sensitive_eval.py \
  --output docs/COST_SENSITIVE_RESULTS.json \
  --cache-prefixes lr,rf,if
```

The script never retunes a threshold and never uses test labels to select a policy. It reads the frozen `models/metrics_{lr,rf,if}_day_based_seed*.json` files, the raw score caches, and the completed D6 result.

## 10. Limitations

- The 5-minute review assumption is not measured. The D8/S7 pilot exists to measure it; simulated analyst feedback is not a substitute.
- `C_FN` and `C_FP` are not supplied by any organization. The ratio curve is illustrative sensitivity, not a dollar ROI.
- The test partition is CIC-IDS-2017 Thursday+Friday. It contains duplicates and a synthetic lab traffic mix. It is not a production network.
- The RF alert-budget results use five seeds; the LR uses one fixed artifact. Their seed uncertainty is therefore not comparable.
- The IF score cache uses `-decision_function`, matching the training script, but the bundle is a legacy artifact with a top-level `preprocessor` pickle dependency.
- The cost model omits engineering, storage, support, false-negative discovery delays, and the cost of alert fatigue. Those omissions make the detector look better than it is, not worse.
- No external dataset, no real attack capture, no human pilot. See [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md) and [`D8_PROSPECTIVE_PILOT_PROTOCOL.md`](D8_PROSPECTIVE_PILOT_PROTOCOL.md).
