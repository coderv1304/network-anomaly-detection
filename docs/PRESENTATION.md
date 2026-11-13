# NetShield: Detecting Attack Families the Model Never Saw

**A bounded, reproducible experiment on CIC-IDS-2017**

Research workbench walkthrough · 12 slides · speaker notes included

> This deck is a presentation companion to `docs/RESEARCH_REPORT.md` and `docs/EVIDENCE_PACKAGE.md`. Every number is traceable to a frozen artifact. It is not a product pitch and does not claim deployment readiness.

---

## Slide 1 — The question

**Can a flow classifier detect attack families it never saw in training?**

- Train on Monday and Tuesday.
- Freeze the threshold on Wednesday.
- Score Thursday and Friday once.
- Treat analyst review capacity as a fixed alert budget.

**Speaker notes:** The point is not whether the model can memorize CIC-IDS-2017. The point is what happens when the test days contain families that are absent from training. That is the realistic failure mode for a supervised detector. The experiment is deliberately bounded: one dataset, one temporal split, five seeds, no production traffic.

**Source:** `docs/EVALUATION_PROTOCOL.md`, `models/model_manifest_rf_day_based_seed42.json`

---

## Slide 2 — The data and the split

| Partition | Days | Flows | Labels present |
|---|---|---:|---|
| Training | Mon–Tue | 975,789 | BENIGN, FTP-Patator, SSH-Patator |
| Validation | Wed | 692,686 | DoS families, Heartbleed |
| Test | Thu–Fri | 1,162,065 | Web attacks, Infiltration, Botnet, PortScan, DDoS |
| Feedback review | Thu | 458,825 | Web attacks, Infiltration |
| Feedback evaluation | Fri | 703,240 | Botnet, PortScan, DDoS |

- Day-based split, not random, to avoid temporal leakage.
- 291,139 test flows belong to labels absent from training.
- The weekday results were inspected during development, so they are development evidence, not a blind confirmation.

**Speaker notes:** The split is the whole design. A random split would let the model see near-duplicate flows from the same capture day and inflate the result. Day-based splitting is harder and more honest. The cost is that the test partition is a different distribution, which is exactly what we want to measure. CIC-IDS-2017 is laboratory data, not enterprise traffic.

**Source:** `docs/RESEARCH_REPORT.md` §3, `docs/EVALUATION_PROTOCOL.md`

---

## Slide 3 — What the model can and cannot output

- Training vocabulary: **BENIGN, FTP-Patator, SSH-Patator**.
- Unseen test families: **Bot, DDoS, Infiltration, PortScan, Web Attack – Brute Force, SQL Injection, XSS**.
- Multiclass macro-F1 collapses to **0.0857** because the model has no output class for the unseen families.
- The useful output is the binary attack score, **1 − P(BENIGN)**.

**Speaker notes:** This is the central constraint. A multiclass classifier cannot invent a class it never saw. Reporting multiclass accuracy would be misleading. The experiment therefore evaluates a binary attack score and reports per-family recall separately. The serving endpoint applies the recorded attack-score threshold to the same Random Forest seed 42 artifact (the argmax label is retained for audit), and its three-class output vocabulary is why the Analyze view looks quiet on attack-heavy samples; the workbench says this explicitly.

**Source:** `models/metrics_rf_day_based_seed42.json`, `docs/MODEL_CARD.md`

---

## Slide 4 — Baselines

Seeds 42–46, mean ± standard deviation, frozen threshold, held-out test.

| Model | PR-AUC | ROC-AUC | Recall | Test FPR |
|---|---:|---:|---:|---:|
| Random Forest | 0.7472 ± 0.0749 | 0.7722 ± 0.0742 | 0.5830 ± 0.1479 | 4.11% ± 3.27% |
| Logistic Regression | 0.4306 | 0.7001 | 0.0352 | 2.66% |
| Isolation Forest | 0.3523 ± 0.0129 | 0.6758 ± 0.0268 | 0.0046 ± 0.0091 | 1.16% |

**Speaker notes:** Random Forest is the strongest baseline by PR-AUC, but the spread is large. The five-seed standard deviation on recall is 14.8 points and on FPR is 3.3 points. That is not a stable operating point. Logistic Regression and Isolation Forest are included to show that the result is not an artifact of one model family. Isolation Forest is unsupervised and has the lowest false-positive rate, but it detects almost nothing at the frozen threshold.

**Source:** `docs/summary_metrics.json`

---

## Slide 5 — The threshold does not survive the day shift

| Field | Seed 42 |
|---|---:|
| Frozen threshold | 0.002515 |
| Validation FPR | 0.5223% |
| Test FPR | 0.7254% |
| Test recall | 57.9428% |
| Test precision | 96.3900% |
| Test alert rate | 15.0604% |

- Threshold selected on Wednesday at maximum FPR 1%.
- Five-seed mean test FPR: **4.11% ± 3.27%**.
- Highest seed in the set: **7.85%**.
- Seed 42 alone looks acceptable; the seed distribution does not.

**Speaker notes:** This is a negative result worth stating plainly. A threshold frozen on one day does not preserve a false-alarm bound on later days. Reporting only seed 42 would hide the instability. The workbench shows both the seed-42 row and the five-seed mean. The correct conclusion is not “the threshold works”; it is “the threshold is brittle and needs recalibration or a different operating policy.”

**Source:** `models/metrics_rf_day_based_seed42.json`, `docs/summary_metrics.json`

---

## Slide 6 — Where the model fails

Random Forest seed 42, frozen threshold, held-out test.

| Attack family | Support | Detected | Recall |
|---|---:|---:|---:|
| Bot | 1,966 | 22 | 1.12% |
| Web Attack – SQL Injection | 21 | 9 | 42.86% |
| PortScan | 158,930 | 85,286 | 53.66% |
| Infiltration | 36 | 20 | 55.56% |
| DDoS | 128,027 | 81,380 | 63.56% |
| Web Attack – Brute Force | 1,507 | 1,367 | 90.71% |
| Web Attack – XSS | 652 | 610 | 93.56% |

**Speaker notes:** The model is not uniformly bad. It catches most XSS and brute-force flows. It catches about two-thirds of DDoS and half of PortScan. It misses almost all Botnet. Infiltration has only 36 flows, so the 55.56% estimate is unstable. The per-family table is the most useful diagnostic in the package because it shows which families drive the aggregate recall.

**Source:** `models/metrics_rf_day_based_seed42.json` → `attack_family_detection`

---

## Slide 7 — The alert queue is pure but incomplete

Random Forest seed 42, Friday evaluation (703,240 flows).

| Budget | K | Precision@K | Attack recall | Botnet recall |
|---|---:|---:|---:|---:|
| Top-50 | 50 | 100.00% | 0.017% | 0.00% |
| Top-500 | 500 | 99.60% | 0.172% | 0.00% |
| 10 per 10,000 | 703 | 98.15% | 0.239% | 0.00% |
| 50 per 10,000 | 3,516 | 97.50% | 1.186% | 0.00% |
| 100 per 10,000 | 7,032 | 98.73% | 2.403% | 0.051% |

- Precision stays at or above 97.5%.
- Recall stays in the low single digits.
- The queue is dominated by high-confidence DDoS and PortScan flows.
- Botnet remains effectively invisible.

**Speaker notes:** A budget is review capacity, not a probability cut-off. The top of the ranking is accurate but narrow. An analyst reviewing the top 7,032 flows would see mostly real attacks, but would still capture only 2.4% of all Friday attacks and essentially no Botnet. This is the operational trade-off the workbench is built to show. Do not present high precision as success without the recall column.

**Source:** `models/feedback_simulation_results.json` → seed 42 no-feedback alert-budget evaluation

---

## Slide 8 — Simulated feedback did not help

Fifty runs: five seeds × ten policy/budget cells (no feedback plus four policies × three budgets).

| Policy | Budget | Friday PR-AUC | Botnet recall |
|---|---:|---:|---:|
| No feedback | 0 | 0.8561 ± 0.0530 | 0.94% ± 0.82% |
| Uncertainty | 100 | 0.8610 ± 0.0471 | 0.90% ± 0.83% |
| Uncertainty | 250 | 0.8343 ± 0.0146 | 0.93% ± 0.77% |
| Top-alert | 250 | 0.8276 ± 0.0696 | 20.35% ± 10.62% |

- Best mean beats no feedback by 0.005 against a spread of about 0.05.
- Uncertainty at B=250 is worse than no feedback.
- Top-alert B=250 is a high-variance outlier, not a reliable improvement.
- Thursday feedback contains Web Attacks and Infiltration; Friday is Botnet, PortScan, and DDoS.

**Speaker notes:** This is a simulation, not a human study. It assumes every selected Thursday flow is labelled instantly and correctly. Even under that generous assumption, no policy produces a clear, stable improvement. The top-alert B=250 Botnet number looks dramatic, but the spread is 10.6 points and the PR-AUC is lower than no feedback. Treat it as an outlier. The negative result is the finding.

**Source:** `models/feedback_simulation_results.json`, `docs/FEEDBACK_SIMULATION.md`

---

## Slide 9 — Drift monitoring: useful for volumetric attacks, not stealth

| Window | Warning | Degraded | Verdict |
|---|---|---|---|
| Tue KnownAttacks | Yes | No | False warning |
| Wed DoS/Heartbleed | Yes | Yes | True warning |
| Thu AM WebAttacks | No | Yes | Missed degradation |
| Thu PM Infiltration | Yes | No | False warning |
| Fri AM Botnet | No | Yes | Missed degradation |
| Fri PM PortScan | Yes | Yes | True warning |
| Fri PM DDoS | Yes | Yes | True warning |

**Summary:** 3 true warnings, 2 false warnings, 2 missed degradations, 0 correctly quiet.

**Speaker notes:** The drift monitor is not a safety net. It catches large distribution shifts such as DDoS and PortScan, but it misses stealthy Web Attacks and Botnet. It also produces false warnings. Drift warnings should trigger human audit, not automatic threshold changes or blocking. The audit is included because it is a real negative result, not because it supports deployment.

**Source:** `models/drift_monitoring_results.json`, `docs/DRIFT_MONITORING.md`

---

## Slide 10 — Real, sample, prediction, simulation

| Source | What it is | Claim status |
|---|---|---|
| CIC-IDS-2017 records | Labelled laboratory capture | Real dataset records |
| Built-in samples | 1,500-row head slices | Real records, sample slice |
| Uploaded files | User CSV, PCAP, or PCAPNG | Real input, unverified labels |
| Model output | Serving artifact predictions | Prediction, not ground truth |
| Feedback simulation | Perfect, instant labels on Thursday | Simulation, not a human study |
| Live capture | Experimental parser | Unvalidated prototype |

**Speaker notes:** The workbench distinguishes these six categories on purpose. A predicted label is not a confirmed attack. A sample slice is not a representative test set. A simulation is not a human study. Live capture is not validated. If a slide or a console blurs those distinctions, it is overclaiming. The provenance view repeats this table next to the model hash and feature-parity audit.

**Source:** `templates/index.html` → Model and provenance view

---

## Slide 11 — Provenance and reproducibility

- Evaluated model: `models/model_bundle_rf_day_based_seed42.pkl`
- SHA-256: `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`
- Serving model: `models/model_bundle_rf_day_based_seed42.pkl`, Random Forest, three classes (same bytes as the evaluated artifact)
- Serving SHA-256: `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`
- Registry version: `serving-rf-day-based-seed42-v1`, calibration `uncalibrated`
- Dataset hashes: recorded in the manifest
- Environment: Python 3.12.10, scikit-learn 1.5.2, pandas 2.2.3, NumPy 1.26.1, Flask 2.3.2
- Reproduction: `run_all_baselines.bat`, `run_feedback_simulation.bat`, `run_drift_monitor.bat`, `verify_feature_parity.bat`

**Speaker notes:** Serving, evaluation, and gating now use the same artifact: the Random Forest seed 42 bundle, verified by SHA-256 against the registry entry. That closes the provenance gap; it does not make the model accurate. The Analyze view states this in the interface, and it is still uncalibrated, so no confidence percentage is shown. If someone asks why the Analyze view looks quiet on a DDoS-heavy sample, the answer is the serving model's three-class output vocabulary, not a research result.

**Source:** `docs/EVIDENCE_PACKAGE.md` §5, `templates/index.html` → Model and provenance view

---

## Slide 12 — What the evidence does not support

- Deployment readiness or production intrusion detection.
- Real-time blocking or automated response.
- Novel or zero-day attack detection.
- Improved detection from analyst feedback in a real SOC.
- Validated accuracy on live network interfaces.
- A calibrated probability that a given flow is an attack.
- Superiority over commercial or production IDS products.

**And what it does support:**

- A day-based split with reproducible partition sizes.
- RF PR-AUC around 0.75 across five seeds.
- Threshold instability under day shift.
- Botnet near-invisibility at the frozen threshold and across the feedback grid.
- A live-capture parity gap: the upload parser now covers 80/80 features, but the two extractors disagree numerically and the live path drops ICMP and IPv6.

**Speaker notes:** Close on the negative results. The value of the package is that it makes the failure modes specific and reproducible. The next step is not a deployment; it is a preregistered confirmatory run with an untouched final holdout, a calibrated threshold procedure, and a real analyst study if feedback is the question. The workbench is a research instrument, not a product demo.

**Source:** `docs/RESEARCH_REPORT.md` §9, `docs/EVIDENCE_PACKAGE.md` §13

---

## Appendix A — One-line summary

> A Random Forest trained on two days of CIC-IDS-2017 reaches PR-AUC 0.75 across five seeds, but its threshold is brittle, its alert queue misses most attacks, Botnet is effectively undetected, simulated feedback does not produce a stable gain, and live capture does not reproduce the offline feature schema. The result is a reproducible negative result, not a deployment claim.

## Appendix B — Where to look

| Question | Artifact |
|---|---|
| Full narrative | `docs/RESEARCH_REPORT.md` |
| Hashes, licenses, commands, claim audit | `docs/EVIDENCE_PACKAGE.md` |
| Baseline metrics | `docs/summary_metrics.json` |
| Per-family and threshold metrics | `models/metrics_rf_day_based_seed42.json` |
| Feedback simulation | `models/feedback_simulation_results.json` |
| Drift audit | `models/drift_monitoring_results.json` |
| Feature parity | `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` |
| Workbench UI | `templates/index.html`, `static/css/workbench.css`, `static/js/workbench.js` |
