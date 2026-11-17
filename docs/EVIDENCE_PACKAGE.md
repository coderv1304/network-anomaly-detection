# NetShield Evidence Package

**Status:** offline research prototype. This package documents what was run, what was measured, and what the evidence does not support. It is not a deployment approval, a product datasheet, or a claim of production intrusion-detection performance.

**Repository commit at package creation:** `4e6fbe3140be30271c6af9d8437abe6e02e5a3db`  
**Package date:** 2026-11-08 (evidence package); serving-artifact identity, ingest-SLO, alert-budget, encrypted-backup, MFA/OIDC, staging/migration, and preflight updates on 2026-11-12; fail-closed staging tests and expanded secret-scan scope on 2026-11-13.  
**Evidence update:** D2 pipeline audit, D3 controlled baselines, D4 threshold-policy transfer, D5 calibration, D6 rare/unseen-family experiment, D7 external validation, D8/S7 pilot preparation, D9 cost-sensitive release gate, S2 reliability measurements, S3 registry/deployment gate, S4 security scans, S5 operations with Alembic and a staging preflight, S6 onboarding/commercial status, S8 release-gate preparation, P1 live-capture parity, P2 multi-interface capture, and P3 sensor identity added. TOTP MFA, an OIDC authorization-code client, a `staging` profile, an Alembic baseline with a startup revision guard, and `scripts/preflight.py` are implemented and tested. They are code-level controls, not operated evidence. The registry-active serving artifact is the evaluated Random Forest seed 42 bundle, and the 20 flows/s ingest SLO passes after batching and WAL tuning. The working tree is uncommitted; artifact hashes below identify the exact files used.  
**Artifact root:** repository root

---

## 1. Research question

Can a supervised flow classifier trained on two days of CIC-IDS-2017 detect attack families that never appear in its training partition, and how does the answer change when analyst review capacity is treated as a fixed alert budget?

The experiment separates three questions:

1. **Binary detection:** attack versus benign on Thursday and Friday, with the threshold frozen on Wednesday validation.
2. **Alert burden:** what a fixed Top-K or rate-based review queue captures, and which families it misses.
3. **Feedback value:** whether a simulated analyst labelling a small Thursday sample improves Friday detection.

The workbench answers these with frozen JSON artifacts. It does not retrain, re-tune, or invent values at page load.

---

## 2. Data and license

| Item | Value |
|---|---|
| Dataset | CIC-IDS-2017 |
| Source | Canadian Institute for Cybersecurity, University of New Brunswick |
| License / terms | Academic, non-commercial research use |
| Total flows after cleaning | 2,830,540 |
| Feature schema | 80 CICFlowMeter flow features |
| Capture setting | Controlled laboratory VLAN with scripted attacks |
| Claim boundary | Laboratory data, not production enterprise traffic |

CIC-IDS-2017 is real labelled capture data, but it is not a sample of a production network. The attacks were generated with scripted tools in a controlled environment. Do not describe it as synthetic traffic or as representative enterprise telemetry.

The repository does not redistribute the raw CIC-IDS-2017 CSVs. It includes derived sample slices under `data/samples/` and records the raw dataset hashes in the model manifest.

### 2.1 Dataset hashes

The following SHA-256 values are copied from `models/model_manifest_rf_day_based_seed42.json`:

| Source CSV | SHA-256 |
|---|---|
| `Monday-WorkingHours.pcap_ISCX.csv` | `96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815` |
| `Wednesday-workingHours.pcap_ISCX.csv` | `ed538e85b84181e8897dedb3d37d365982f44b27eccd67c477581a8b65f3d170` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | `e3deaff483d18b53b100a441dff9b8919416df8876b4edcc0f0d1e4bf48397d0` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | `d74238e054023c8bd4d8056650463cadb25c100fb0e26ebd4272c07b5c022c4b` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | `c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21` |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | `1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08` |

### 2.2 Derived sample hashes

| File | Rows | SHA-256 |
|---|---:|---|
| `data/samples/test_dataset.csv` | 5,204 | `1aaa522a86da6873670d53fb9ec8d0e1910270d28effcfca79f895c7b6bbd0e0` |
| `data/samples/network_test_dataset.csv` | 15,000 | `7e0538b1969d5087acfcab4e25fa2259bd031aaee401f829d2ec80f52736ca8b` |

These are 1,500-row slices in the Analyze view. The slice is not a random sample of the full dataset. It is a deterministic head slice of the derived sample file. The Analyze view labels it as a sample, not as a representative test set.

---

## 3. Split protocol

The split is by day, not random, to avoid temporal leakage.

| Partition | Days | Flows | Labels present | Role |
|---|---|---:|---|---|
| Training | Monday to Tuesday | 975,789 | BENIGN, FTP-Patator, SSH-Patator | Fit model and label vocabulary |
| Validation | Wednesday | 692,686 | DoS families, Heartbleed | Freeze threshold at maximum FPR 1% |
| Test | Thursday to Friday | 1,162,065 | Web attacks, Infiltration, Botnet, PortScan, DDoS | Held-out scoring |
| Feedback review | Thursday | 458,825 | Web attacks, Infiltration | Simulated feedback selection only |
| Feedback evaluation | Friday | 703,240 | Botnet, PortScan, DDoS | Untouched Friday evaluation |

The test partition contains 291,139 flows from labels that never appear in training. The model's multiclass output vocabulary is therefore incomplete by construction.

The D2 audit reports slightly larger raw row counts than this table (train 975,827, validation 692,703, test 1,162,213) because the training loader removes within-partition duplicates after the audit. The audit also finds 252,672 validation rows from DoS families absent from training, so threshold selection is exposed to families the model never learned.

**Integrity rules:**

- No Thursday or Friday labels are used to fit the model or select the threshold.
- The threshold is selected on Wednesday validation only.
- Feedback selection uses Thursday flows; Friday is scored after feedback.
- The weekday results were inspected during development. They are development evidence, not a preregistered blind confirmation.

---

## 4. Feature definitions and provenance

The model consumes 80 CICFlowMeter features. The complete ordered list is recorded in:

- `models/model_manifest_rf_day_based_seed42.json` → `features`
- `models/model_bundle_rf_day_based_seed42.pkl` → `feature_names`

Feature groups include:

- Flow identity and size: source and destination port, protocol, flow duration, packet and byte totals, forward and backward packet lengths.
- Rate and timing: flow bytes/s, packets/s, inter-arrival time mean/std/max/min, forward and backward IAT statistics, active and idle statistics.
- TCP flags and headers: FIN, SYN, RST, PSH, ACK, URG, CWE, ECE, header lengths, initial window sizes.
- Subflow and bulk statistics: subflow packet and byte counts, bulk rate and bulk packet statistics.
- Packet-length distribution: minimum, maximum, mean, standard deviation, variance, average packet size.

### 4.1 Live-capture and upload-parser parity

The project has two extraction paths, and they fail parity in different ways:

- **Live path:** `live_capture.py` uses PyFlowMeter. It maps all 80 training feature names through `feature_mapper.py`, but its `ip and (tcp or udp)` filter drops ICMP and IPv6, and its numeric values disagree with the upload parser on rate, inter-arrival, and packet-length statistics.
- **Upload path:** `pcap_parser.pcap_to_flows` uses Scapy. It produces 57 of the 80 training features and fills 6 more with constants.

| Measure | Value |
|---|---:|
| Required training features | 80 |
| Live PyFlowMeter path: schema names mapped | 80 |
| Live flows vs upload-reference flows on the P1 fixture | 4 vs 6 |
| Reference-only flows dropped by the live filter (ICMP, IPv6) | 2 (33.3%) |
| Unmatched live flows / ambiguous live flows | 0 / 0 |
| Upload Scapy path: features produced | 80 |
| Upload path: missing features | 0 |
| Upload path: dummy constants | 0 |

The upload parser now measures TCP window sizes, forward and backward header lengths, PSH/URG flags, bulk-rate statistics, `act_data_pkt_fwd` / `min_seg_size_forward`, active/idle statistics, and packet-length extremes. Before the fix it produced 57 of 80 features with 23 missing and 6 constants; that history is retained in `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` as a regression check.

Neither path was compared against a CICFlowMeter-generated row from the same bytes, because no CICFlowMeter binary or source PCAP is available in this repository. Agreement between the two Python extractors is necessary but not sufficient for training-schema parity.

**Consequence:** live-capture predictions are unvalidated. The live path does not reproduce the offline feature distribution or flow coverage. Do not claim live parity or production accuracy.

Full audit: `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md`. The older `docs/FEATURE_PARITY_LIVE_CAPTURE.md` and `training/feature_parity.py` cover the Scapy upload parser against a reference CSV; they are not evidence about the PyFlowMeter live path.

---

## 5. Model artifacts and hashes

### 5.1 Evaluated research artifact

| Field | Value |
|---|---|
| File | `models/model_bundle_rf_day_based_seed42.pkl` |
| Algorithm | Random Forest, 100 trees |
| Task | Multiclass over BENIGN, FTP-Patator, SSH-Patator; binary attack score derived as 1 − P(BENIGN) |
| Seed | 42 |
| Features | 80 |
| SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Python | 3.12.10 |
| scikit-learn | 1.5.2 |

Metrics: `models/metrics_rf_day_based_seed42.json`  
Manifest: `models/model_manifest_rf_day_based_seed42.json`

### 5.2 Serving artifact

| Field | Value |
|---|---|
| File | `models/model_bundle_rf_day_based_seed42.pkl` |
| Algorithm | Random Forest |
| Output classes | BENIGN, FTP-Patator, SSH-Patator |
| SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Model version | `serving-rf-day-based-seed42-v1` (registry active) |
| Feature schema | `cic-ids-2017-80f-45cd75ce849b` |
| Threshold applied | Yes. `1 - P(BENIGN) >= 0.002515048908954043`; argmax label retained for audit. |
| Threshold policy | `global_validation_max_fpr` (max FPR 0.01) |
| Calibration | `uncalibrated` (no confidence shown; available isotonic artifact fails the 0.05 ECE gate) |

Serving, evaluation, and gating now load the same artifact bytes: the registry-active serving hash equals the evaluated seed 42 manifest hash. The model still cannot emit DDoS, PortScan, Bot, Infiltration, or web-attack labels, and it is uncalibrated. The Analyze view states this in the interface. Matching artifact identity fixes provenance; it does not make the detector accurate or externally validated.

### 5.3 Supporting artifact hashes

| Artifact | SHA-256 |
|---|---|
| `models/metrics_rf_day_based_seed42.json` | `80d3bf2346ed1d15c6a9919abfad20151931f8b3c13630b90d30d80271fce964` |
| `models/feedback_simulation_results.json` | `2f35d87a55ca5dc9467793a7e719687b03c899d9b0df11d0594f361c98efcb16` |
| `models/drift_monitoring_results.json` | `dc3d5077a9accb86091555905482844228e44d89f758e116b277190ed71fc0a6` |
| `docs/summary_metrics.json` | `e39fa6e42025aefc4632428ee1b2cc9dff3194745fb4908f2a76c899c0a2334a` |
| `docs/d6_unseen_family_results.json` | `322dce2ab442128c9c36049981e735abc6291477eef5a804676102338ad19109` |
| `docs/COST_SENSITIVE_RESULTS.json` | `dcbf1fd94836a322513325a999fcad007fff8b2d6a976791045aed961d78d124` |
| `docs/s7_pilot_analysis_selftest.json` | `555caec3e1d70193a3497b4bfcdb2f67b58d49c431c47061fcc53440f39ebc7c` |
| `docs/s8_release_gate.json` | `6ef0921ce05373070d2187da25cae0e15b6e13e0e16a66400b584d1a3168330f` |
| `docs/s8_external_review.json` | `2e996e5859509e6c2696a73c7588c9cbce70a262aaeda191ae41bec13fa6e4ab` |
| `docs/security_gate.json` | `815832796b5a31c16842f8ea5c7736751f7bb26fbac1163848ba77eb50abbe8b` |
| `docs/secret_scan.json` | `9945a86324b73f461c7705d026f49b3c00663e1b69e02fb6f37afb23464588e8` |
| `docs/deployment_check.json` | `757d2ff8692bc64e431a29bc4237f89871a8f9b9e3127f464d5c5697e880d4f3` |
| `scripts/release_gate.py` | `e604a024ee89b50da32742da83127ffc33db3d513d4ad3211864be7b68cb5d48` |
| `scripts/secret_scan.py` | `c59bc90bbce798e4c3097ba9b099b5224fdded17802601b2680c9deead4ba2f1` |
| `tests/test_sensor_identity.py` | `2aaf435e998e21820cfd312e23a4cb353b17c92a45c455c7f1c703bb31e5a678` |
| `tests/test_release_gate.py` | `a771f892e13beccab18ff62f0fab047dc59d56d65d8c915a5a4feec323aaccb3` |
| `requirements.txt` | `a002047f9a22c6d36c6e94f0636dfa6f4b71ca599c94d0a68e2a1ba0bb8a8702` |
| `requirements-runtime.txt` | `f4005921fa01ba83ec5a7ae0731a79f3ba1f6904ce49c03f61d3c0fba3615c66` |
| `app.py` | `a05b111e025675f0e12f8a8d0831a49b5b96c11a0b8f0b479341fbf69e9069a8` |
| `mfa.py` | `c26900276ad0a7ed02714945e6becc1bd990a1a9468f10c4a327a76c25d9ecaa` |
| `oidc.py` | `f6d5ab4d3bc4e21c7aa5ca4e0922cc504d23763dcbd3b8dd0dd1d307bc73f06d` |
| `migrations_runtime.py` | `4054b780467fb958e39855c8986f28015396d760b10bb6e9fcac344307a2e9df` |
| `alembic.ini` | `fe45d42f852b5cdf90d7e62a85d6372209248a1f2e0d79b4b70c17be750f8032` |
| `migrations/env.py` | `1120de400d92d37650febb50aa5685ed68982f5578694812ba88af370448f3e2` |
| `migrations/versions/f68710d807f3_baseline_schema.py` | `8caedfeaee13c0d181d06c04ece321888ae39164d42477f6e8d8162a666d0463` |
| `scripts/preflight.py` | `fb20dde4a24e3cf64c7b29cc96c59e4452f20790cad69bd2085e397109a2c472` |
| `scripts/mfa_admin.py` | `bb33dffb6745c22a0b9ee13c9e5fed10862c1222556faf9773c92eb3f8a5047c` |
| `docs/STAGING_AND_MIGRATIONS.md` | `194ec3c40fca19adf11d26c07ae3dd12336dcdcf4b878ec9b4532a92ca1321e7` |
| `tests/test_staging_config.py` | `054c37a23578cbc0e19b9a4b47757efcec18b6ecfb9500f6e72b67c7b0e46fdb` |
| `tests/test_mfa.py` | `8c01134cfc5cb2d1dd02f794f501c1b495c36fd9aadd9de7320f5f1e679f1eaf` |
| `tests/test_oidc.py` | `c91172e0683952787e229ab68f7c9276281cfd437245ea4a28a8e81c99159350` |
| `tests/test_migrations.py` | `4d01a3079941560351a915e2d573b7a5bc58420e990723babe6bd5b1aa226114` |
| `tests/test_preflight.py` | `e77f80abaee49ea03e21922b2819d075328d348135ca5760cd3bee01eda1a1e1` |
| `templates/account.html` | `62e64155b245794ce218cc2ad802ea16c79df2c3e91ee125f48714fb13f0a5d6` |
| `static/js/account.js` | `6345e73ad5e86dd980811ca40c5c6cc02a52f85d175bc0ca4871166aa66b2c23` |

Verify a hash on Windows:

```bat
certutil -hashfile models\model_bundle_rf_day_based_seed42.pkl SHA256
```

Verify a hash on macOS or Linux:

```bash
sha256sum models/model_bundle_rf_day_based_seed42.pkl
```

---

## 6. Threshold procedure

1. Train on Monday and Tuesday.
2. Score Wednesday validation flows with the binary attack score, 1 − P(BENIGN).
3. Select the highest threshold whose validation FPR is at most 1%.
4. Freeze that threshold.
5. Score Thursday and Friday once with the frozen threshold.

| Field | Seed 42 |
|---|---:|
| Frozen threshold | 0.002515 |
| Validation FPR | 0.5223% |
| Validation recall | 4.5870% |
| Test FPR | 0.7254% |
| Test recall | 57.9428% |
| Test precision | 96.3900% |
| Test alert rate | 15.0604% |

**Important:** the threshold is selected at a 1% validation FPR, but the observed test FPR can exceed it. Across seeds 42–46, the RF mean test FPR is 4.11% ± 3.27%. Seed 42 is 0.73%; the highest seed in the set reaches 7.85%. A Wednesday-frozen threshold does not guarantee a Friday false-alarm bound. The full per-day and per-family breakdown is in [THRESHOLD_POLICY_V2.md](THRESHOLD_POLICY_V2.md).

The serving app applies the threshold recorded in the registry-active Random Forest bundle (`1 - P(BENIGN) >= 0.002515048908954043`). Serving, evaluation, and gating use the same artifact bytes, verified by SHA-256. The serving artifact is registered as uncalibrated, so the UI shows no confidence percentage. D4 and D5 describe this same RF configuration; their held-out results still fail the detection gate.

---

## 7. Baselines

Seeds 42–46, mean ± standard deviation, frozen threshold, held-out test partition.

| Model | Type | PR-AUC | ROC-AUC | Recall at frozen threshold | Test FPR | Alert rate | Fit seconds |
|---|---|---|---:|---:|---:|---:|---:|
| Random Forest (100 trees) | Supervised | 0.7472 ± 0.0749 | 0.7722 ± 0.0742 | 0.5830 ± 0.1479 | 0.0411 ± 0.0327 | 17.68% ± 5.12% | 65.7 ± 5.2 |
| Logistic Regression (L2) | Linear | 0.4306 ± 0.0000 | 0.7001 ± 0.0000 | 0.0352 ± 0.0000 | 0.0266 ± 0.0000 | 2.88% ± 0.00% | 66.1 ± 5.3 |
| Isolation Forest (100 trees) | Unsupervised | 0.3523 ± 0.0129 | 0.6758 ± 0.0268 | 0.0046 ± 0.0091 | 0.0116 ± 0.0003 | 0.99% ± 0.23% | 3.4 ± 0.2 |

Random Forest is the strongest baseline by PR-AUC. Logistic Regression and Isolation Forest are controlled comparisons, not recommended detectors.

---

## 8. Per-family results

Random Forest seed 42, held-out test partition, frozen threshold. Sorted by recall.

| Attack family | Support | Detected | Recall | Seen in training |
|---|---:|---:|---:|---|
| Bot | 1,966 | 22 | 1.12% | No |
| Web Attack – SQL Injection | 21 | 9 | 42.86% | No |
| PortScan | 158,930 | 85,286 | 53.66% | No |
| Infiltration | 36 | 20 | 55.56% | No |
| DDoS | 128,027 | 81,380 | 63.56% | No |
| Web Attack – Brute Force | 1,507 | 1,367 | 90.71% | No |
| Web Attack – XSS | 652 | 610 | 93.56% | No |

Infiltration (36 flows) and SQL Injection (21 flows) have very small supports. Their recall estimates are unstable. Botnet is effectively undetected at the frozen threshold. The multiclass macro-F1 is 0.0857 because the model has no output class for any of these families.

---

## 9. Alert-budget findings

Random Forest seed 42, Friday evaluation partition (703,240 flows; 288,923 attacks; 414,317 benign). A budget is review capacity, not a probability threshold.

| Budget | K | Precision@K | Attack recall | FP per 10k benign | Botnet recall | DDoS recall | PortScan recall |
|---|---:|---:|---:|---:|---:|---:|---:|
| Top-50 | 50 | 100.00% | 0.017% | 0.00 | 0.00% | 0.00% | 0.031% |
| Top-100 | 100 | 100.00% | 0.035% | 0.00 | 0.00% | 0.00% | 0.063% |
| Top-250 | 250 | 100.00% | 0.087% | 0.00 | 0.00% | 0.00% | 0.157% |
| Top-500 | 500 | 99.60% | 0.172% | 0.05 | 0.00% | 0.00% | 0.313% |
| 10 per 10,000 | 703 | 98.15% | 0.239% | 0.31 | 0.00% | 0.00% | 0.434% |
| 50 per 10,000 | 3,516 | 97.50% | 1.186% | 2.12 | 0.00% | 1.143% | 1.236% |
| 100 per 10,000 | 7,032 | 98.73% | 2.403% | 2.15 | 0.051% | 3.864% | 1.255% |

**Finding:** precision stays high because the top of the ranking is dominated by high-confidence DDoS and PortScan flows. Attack recall stays low because those families contain many flows and Botnet ranks below them. Even at 100 alerts per 10,000 flows, Botnet recall is 0.051% and overall attack recall is 2.403%. The queue is pure and misses most attacks.

---

## 10. Simulated feedback experiment

Fifty runs: five seeds (42–46) × ten policy/budget cells (no feedback plus four policies × three budgets). All values are mean ± standard deviation across seeds.

| Policy | Budget B | Friday PR-AUC | Recall at frozen threshold | Test FPR | Test precision | Botnet recall |
|---|---:|---:|---:|---:|---:|---:|
| No feedback | 0 | 0.8561 ± 0.0530 | 0.5805 ± 0.1489 | 0.0061 ± 0.0024 | 0.9850 ± 0.0057 | 0.94% ± 0.82% |
| Random sampling | 50 | 0.8083 ± 0.0312 | 0.4513 ± 0.0776 | 0.0072 ± 0.0026 | 0.9766 ± 0.0115 | 0.72% ± 0.89% |
| Top-alert triage | 50 | 0.8467 ± 0.1152 | 0.5889 ± 0.2777 | 0.0110 ± 0.0058 | 0.9668 ± 0.0298 | 1.22% ± 1.02% |
| Uncertainty sampling | 50 | 0.8585 ± 0.0500 | 0.6008 ± 0.1324 | 0.0125 ± 0.0054 | 0.9699 ± 0.0141 | 0.78% ± 0.57% |
| Random sampling | 100 | 0.8458 ± 0.0556 | 0.5559 ± 0.1600 | 0.0071 ± 0.0038 | 0.9830 ± 0.0055 | 1.01% ± 0.90% |
| Top-alert triage | 100 | 0.8148 ± 0.0814 | 0.4931 ± 0.2129 | 0.0118 ± 0.0053 | 0.9612 ± 0.0217 | 1.09% ± 1.06% |
| Uncertainty sampling | 100 | 0.8610 ± 0.0471 | 0.6071 ± 0.1312 | 0.0135 ± 0.0087 | 0.9681 ± 0.0212 | 0.90% ± 0.83% |
| Random sampling | 250 | 0.7971 ± 0.0531 | 0.4376 ± 0.1368 | 0.0097 ± 0.0063 | 0.9675 ± 0.0228 | 1.10% ± 0.78% |
| Top-alert triage | 250 | 0.8276 ± 0.0696 | 0.5355 ± 0.1715 | 0.0194 ± 0.0131 | 0.9451 ± 0.0514 | 20.35% ± 10.62% |
| Uncertainty sampling | 250 | 0.8343 ± 0.0146 | 0.5294 ± 0.0451 | 0.0131 ± 0.0061 | 0.9664 ± 0.0143 | 0.93% ± 0.77% |

**Finding:** no policy beats the no-feedback reference by a margin larger than the seed spread. The best mean is uncertainty sampling at B=100 (0.8610 versus 0.8561), a 0.005 difference against a standard deviation of roughly 0.05. Uncertainty sampling at B=250 falls to 0.8343. The top-alert B=250 Botnet result is a high-variance outlier: 20.35% ± 10.62%, with PR-AUC 0.8276 ± 0.0696. It is not a reliable improvement.

**This is a simulation, not a human study.** It assumes perfect, instantaneous labels. It does not measure analyst accuracy, delay, fatigue, label noise, or queue abandonment.

---

## 11. Drift-monitoring audit

Unsupervised drift monitoring used score PSI and two-sample Kolmogorov–Smirnov tests on six high-importance features. Warnings did not use test labels; labels were used only for retrospective audit.

| Window | Flows | Flagged features | Warning | Degraded | Test recall | Verdict |
|---|---:|---:|---|---|---:|---|
| Tue KnownAttacks | 445,905 | 2 / 6 | Yes | No | 100.0% | False warning |
| Wed DoS/Heartbleed | 692,686 | 6 / 6 | Yes | Yes | 0.0% | True warning |
| Thu AM WebAttacks | 170,365 | 0 / 6 | No | Yes | 0.0% | Missed degradation |
| Thu PM Infiltration | 288,460 | 5 / 6 | Yes | No | 0.0% | False warning |
| Fri AM Botnet | 191,031 | 1 / 6 | No | Yes | 0.0% | Missed degradation |
| Fri PM PortScan | 286,466 | 6 / 6 | Yes | Yes | 0.0% | True warning |
| Fri PM DDoS | 225,743 | 6 / 6 | Yes | Yes | 0.0% | True warning |

**Summary:** three true warnings, two false warnings, two missed degradations, zero correctly quiet. The monitor is most reliable for volumetric attacks (DDoS, PortScan) and least reliable for stealthy attacks (Web Attacks, Botnet). Drift warnings are audit signals only; they must not automatically change thresholds, firewall rules, or blocking behavior.

---

## 12. Uncertainty and statistical reporting

- All baseline and feedback values are mean ± standard deviation across seeds 42–46.
- No confidence intervals, significance tests, or multiple-comparison correction were applied.
- Differences smaller than the seed spread are reported as inconclusive, not as improvements.
- Infiltration (36 test flows) and SQL Injection (21 test flows) have unstable recall estimates.
- The feedback experiment is a simulation with perfect labels and no delay.
- The weekday results are development evidence, not a preregistered confirmatory test.

---

## 13. Limitations and unsupported claims

**Supported by the artifacts:**

- The day-based split and partition sizes.
- The D2 pipeline defects: duplicate physical `Fwd Header Length` header, `cp1252` encoding for Thursday WebAttacks, 288,602 trailing unlabeled rows, within- and cross-partition duplicates, and unseen-family rows in validation and test.
- RF PR-AUC around 0.75 across five seeds.
- Test FPR above the 1% validation target in the five-seed mean.
- Botnet near-invisibility at the frozen threshold and across the feedback grid.
- The D6 negative result: across seven predeclared arms and five seeds, no arm reaches Bot recall ≥ 0.50 at ≤ 1% FPR. The best Bot arm (family-aware augmentation) reaches 20.7% ± 16.6% but at 8.65% ± 1.37% FPR and a 29.4% alert rate; the isolation, PCA, Mahalanobis, and hybrid arms fail as well.
- The D9 cost result: the served Random Forest breaks even at `C_FN/C_FP ≈ 1.21` at its frozen threshold and `≈ 1.11` at a 100-alert-per-10k budget, but recovers only 3.6% of attacks at that budget. The legacy Logistic Regression needed `> 3.26` and `> 4.93`.
- The D9 release gate fails 7 of 9 checks (FPR, alert rate, Bot recall, calibration, external dataset, prospective pilot, site cost model). Artifact identity and five-seed reporting pass. The served RF breaks even at `C_FN/C_FP ≈ 1.21` at its frozen threshold and `≈ 1.11` at a 100-alert budget, so no 9/10 detection claim is supported.
- S7 has not been run: the pre-registration, instruments, export schemas, and analysis harness exist, but there is no design partner, consent, or pilot data.
- The S7 harness self-test is synthetic: it verifies the analysis code path only and is labelled `SYNTHETIC SELF-TEST — NOT PILOT EVIDENCE` with verdict `SELFTEST_ONLY`.
- No controlled baseline passes all predeclared detection gates.
- Live feature parity gaps: the upload parser now covers 80/80 features, but the live path drops ICMP and IPv6 and the two extractors still disagree on some numeric features.
- The latest load test at 20 flows/s measured p95 **164.9 ms** with 100% success, meeting the 250 ms ingest SLO after batch inference, removal of per-row refresh queries, and SQLite WAL tuning. Capacity above 20 flows/s was not re-measured.
- The S8 release gate is machine-checked and currently **FAIL**: 6 pass, 1 fail, 2 blocked. Security, secrets, backup drill, SBOM, artifact identity, and measured ingest SLO pass; the detection gate fails; external review and a real pilot are blocked.
- P3 sensor identity is implemented and tested: flows carry nullable `sensor_id`/`interface`, ingest accepts collector identity, `/api/sensors/summary` is tenant-scoped, and the console filters by sensor. Legacy rows remain unattributed.
- TOTP MFA (RFC 6238 with encrypted secrets, replay rejection, and hashed single-use recovery codes) and an OIDC authorization-code client with PKCE and RS256 verification are implemented and unit-tested. OIDC was tested only against a local fake provider.
- A `staging` profile, Alembic baseline `f68710d807f3`, startup revision guard, and `scripts/preflight.py` exist and are tested. No operated staging environment, real IdP integration, or production migration history exists.

**Not supported by the artifacts:**

- Deployment readiness or production intrusion detection.
- Real-time blocking or automated response.
- Novel or zero-day attack detection.
- Rare-family or Botnet detection capability; the D6 experiment found no arm reaching the Bot recall gate.
- Cost-justified usefulness at an arbitrary cost ratio; no site has supplied `C_FP`, `C_FN`, or a review budget, so D9 reports a sensitivity curve rather than an ROI.
- A completed design-partner pilot, measured onboarding time, alert yield, analyst time, or support load; S7 was not run.
- Improved detection from analyst feedback in a real SOC.
- Validated accuracy on live network interfaces.
- A calibrated probability that a given flow is an attack.
- Superiority over commercial or production IDS products.
- A completed external security or readiness review; `docs/s8_external_review.json` records `not_commissioned`.
- Multi-tenant SaaS operation, per-sensor fleet management, or a production sensor inventory.
- A 9/10 detection score or 8/10–9/10 SaaS readiness.

**Provenance distinctions:**

| Source | What it is | Claim status |
|---|---|---|
| CIC-IDS-2017 records | Labelled flows from a controlled laboratory capture | Real dataset records |
| Built-in samples | 1,500-row head slices of derived sample files | Real records, sample slice |
| Uploaded files | User-supplied CSV, PCAP, or PCAPNG | Real input, unverified labels |
| Model output | Predicted labels from the serving artifact | Prediction, not ground truth |
| Feedback simulation | Perfect, instant labels applied to selected Thursday flows | Simulation, not a human study |
| S7 harness self-test | Synthetic fixture generated by `scripts/pilot_analysis.py` | `SELFTEST_ONLY`; not pilot, human, or customer evidence |
| Live capture | Experimental packet-capture path | Unvalidated prototype |

---

## 14. Environment

| Component | Version |
|---|---|
| OS | Windows (development host) |
| Python | 3.12.10 |
| scikit-learn | 1.5.2 |
| pandas | 2.2.3 |
| NumPy | 1.26.1 |
| Flask | 3.1.3 |
| cryptography | 50.0.2 (encrypted backup drill) |
| Model artifact | `models/model_bundle_rf_day_based_seed42.pkl` for both the research results and the serving endpoint |

Dependency lock: `requirements.txt` (SHA-256 above).

---

## 15. Reproduction commands

Run from the repository root with the virtual environment active.

```bat
REM Create and activate the environment (Windows)
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

REM Baseline training and evaluation, seeds 42-46
run_all_baselines.bat

REM Alert-burden metrics are computed inside baseline evaluation
REM See training/evaluate.py -> evaluate_alert_budgets()

REM Simulated analyst feedback (Phase 5)
run_feedback_simulation.bat

REM Unsupervised drift monitoring (Phase 6)
run_drift_monitor.bat

REM Data/label/feature/split audit (Phase D2)
venv\Scripts\python.exe training\audit_pipeline_v2.py

REM Controlled baseline comparison (Phase D3)
venv\Scripts\python.exe training\baseline_comparison_v2.py

REM S2 load test (start the service with metrics first; see docs/SLO_AND_ONCALL.md)
venv\Scripts\python.exe scripts\load_test.py --base-url http://127.0.0.1:5050 --api-key loadtest-key --rates 20,50,100,200,400 --duration 8 --workers 8 --batch-size 10

REM Live-vs-upload parity audit (Phase P1)
venv\Scripts\python.exe training\parity_live_capture.py

REM Phase 7 reference-CSV vs upload-parser parity audit
verify_feature_parity.bat

REM Aggregate metrics and regenerate summary_metrics.json
venv\Scripts\python.exe scripts\aggregate_metrics.py

REM Start the research workbench
venv\Scripts\python.exe app.py
```

On macOS or Linux, use `source venv/bin/activate` and the equivalent `python` commands. The `.bat` runners are Windows wrappers around the same Python entry points.

**Expected wall-clock time:** approximately 90–120 minutes; baseline training dominates.

### 15.1 Verify the workbench renders frozen artifacts

```bat
curl -s http://127.0.0.1:5000/ | findstr "serving"
```

The response should contain `model_bundle_rf_day_based_seed42.pkl`, `RandomForest`, and the three serving classes. If it does not, the server is running an older template or a different artifact path.

---

## 16. Artifact registry

| Artifact | Role |
|---|---|
| `models/model_bundle_rf_day_based_seed42.pkl` | Evaluated research model and registry-active serving artifact, seed 42 |
| `models/model_manifest_rf_day_based_seed42.json` | Feature list, hashes, trained classes, environment |
| `models/metrics_rf_day_based_seed42.json` | Frozen-threshold metrics, per-family recall, calibration |
| `docs/summary_metrics.json` | Five-seed aggregate metrics for RF, LR, IF |
| `models/feedback_simulation_results.json` | Fifty-run feedback simulation |
| `models/drift_monitoring_results.json` | Seven-window drift audit |
| `docs/RESEARCH_REPORT.md` | Research narrative and corrected results |
| `docs/DATA_PIPELINE_AUDIT.md` | Phase D2 data, label, feature, split, and leakage audit |
| `docs/BASELINE_RESULTS_V2.md` | Phase D3 controlled baseline table and gate results |
| `docs/THRESHOLD_POLICY_V2.md` | Phase D4 threshold-policy transfer across days and seeds |
| `docs/CALIBRATION_V2.md` | Phase D5 calibration, ECE/Brier, reliability diagrams, decision curve |
| `docs/D6_EXPERIMENT_PROTOCOL.md` | Phase D6 predeclared rare/unseen-family protocol |
| `docs/UNSEEN_FAMILY_AND_BOTNET.md` | Phase D6 negative result and per-family breakdown |
| `docs/d6_unseen_family_results.json` | Phase D6 five-seed machine-readable results |
| `docs/EXTERNAL_VALIDATION.md` | Phase D7 external-validation status and real-capture ingest test |
| `docs/D8_PROSPECTIVE_PILOT_PROTOCOL.md` | Phase D8 prospective human-review protocol |
| `docs/D8_PILOT_OUTCOME_TEMPLATE.md` | Phase D8 outcome template (unused; no pilot) |
| `docs/COST_MODEL_AND_RELEASE_GATE.md` | Phase D9 cost model, cost curves, and failed release gate |
| `docs/COST_SENSITIVE_RESULTS.json` | Phase D9 machine-readable cost and gate output |
| `docs/S7_PILOT_PREREGISTRATION.md` | Phase S7 pre-registered design-partner pilot protocol |
| `docs/S7_PILOT_OUTCOME.md` | Phase S7 outcome: not run / blocked |
| `docs/s7_pilot_analysis_selftest.json` | Synthetic harness self-test (not pilot evidence) |
| `docs/S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md` | Phase S8 external-review preparation and nine-check release gate |
| `docs/s8_external_review.json` | Machine-readable external-review record: `not_commissioned` |
| `docs/s8_release_gate.json` | Machine-checked S8 verdict: FAIL (6 pass, 1 fail, 2 blocked) |
| `scripts/release_gate.py` | S8 release-gate aggregator |
| `docs/PHASE_STATUS.md` | Audit of every D/S/P phase and its blocker |
| `tests/test_sensor_identity.py` | P3 sensor identity, filtering, and tenant-isolation tests |
| `docs/OPERATIONS_RUNBOOK.md` | Phase S5 environments, release, rollback, and routine operations |
| `docs/STAGING_AND_MIGRATIONS.md` | Staging profile, Alembic migrations, preflight gate, MFA, and OIDC status |
| `migrations/versions/f68710d807f3_baseline_schema.py` | Alembic baseline schema revision |
| `migrations_runtime.py` | Startup revision guard for staging and production |
| `scripts/preflight.py` | Staging/production preflight gate |
| `mfa.py` | TOTP, encrypted secret storage, and recovery codes |
| `oidc.py` | OIDC discovery, PKCE, code exchange, and RS256 token verification |
| `templates/account.html`, `static/js/account.js` | Self-service MFA enrollment and recovery-code surface |
| `tests/test_mfa.py`, `tests/test_oidc.py`, `tests/test_migrations.py`, `tests/test_preflight.py`, `tests/test_staging_config.py` | Identity, migration, preflight, and fail-closed staging tests |
| `.env.staging.example` | Staging configuration template with placeholders only |
| `docs/INCIDENT_RESPONSE.md` | Phase S5 incident playbooks and escalation |
| `docs/backup_restore_drill.json` | Phase S5 backup/restore drill result |
| `docs/ONBOARDING_AND_SUPPORT.md` | Phase S6 onboarding, support path, and non-commercial status |
| `models/registry/registry.json` | Phase S3 model versions, hashes, threshold/calibration pins, lifecycle history |
| `docs/MODEL_REGISTRY_AND_DEPLOYMENT.md` | Phase S3 promotion, rollback, signing, and deployment-gate process |
| `docs/SECURITY_AND_COMPLIANCE.md` | Phase S4 scans, SBOM, secrets, container, and assurance status |
| `docs/SECURITY_FINDINGS.json` | Phase S4 structured findings tracker and remediation order |
| `docs/PRIVACY_AND_DATA_LIFECYCLE.md` | Phase S4 retention, export, and deletion review |
| `docs/PENETRATION_TEST_PLAN.md` | Phase S4 blocked external penetration-test plan |
| `docs/SLO_AND_ONCALL.md` | Phase S2 SLOs, backpressure, load-test evidence, and on-call model |
| `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` | Phase P1 live-vs-upload parity audit |
| `docs/LIVE_CAPTURE_OPERATIONS.md` | Phase P2 adapter selection and multi-interface ingest evidence |
| `docs/zap/zap_report.json` | Phase S4 OWASP ZAP baseline HTTP assessment |
| `docs/bandit_report.json` | Phase S4 Bandit static-analysis findings |
| `docs/security_gate.json` | Phase S4 actionable-findings gate verdict |
| `docs/FEEDBACK_SIMULATION.md` | Phase 5 aggregate table and analysis |
| `docs/DRIFT_MONITORING.md` | Phase 6 audit and limitations |
| `docs/FEATURE_PARITY_LIVE_CAPTURE.md` | Phase 7 reference-CSV vs upload-parser audit |
| `docs/EVALUATION_PROTOCOL.md` | Split and evaluation integrity rules |
| `docs/MODEL_CARD.md` | Model card and serving caveats |
| `templates/index.html` | Six-view research workbench |
| `static/css/workbench.css` | Workbench design system |
| `static/js/workbench.js` | Analyze view, filters, detail panel, export |

---

## 17. Package verification checklist

- [ ] Confirm the raw dataset hashes against the manifest.
- [ ] Confirm the model hash `fa4c78...1350` for the evaluated RF artifact.
- [ ] Confirm the serving hash `fa4c78...1350` for `models/model_bundle_rf_day_based_seed42.pkl` matches the registry-active artifact.
- [ ] Confirm `docs/summary_metrics.json` matches the baseline table.
- [ ] Confirm `models/feedback_simulation_results.json` contains 50 runs and the ten-row aggregate.
- [ ] Confirm the drift audit reports 3 true warnings, 2 false warnings, 2 missed degradations.
- [ ] Confirm the workbench displays the serving artifact as a Random Forest with three classes.
- [ ] Confirm `docs/DATA_PIPELINE_AUDIT.md` records the duplicate header, encoding, duplicate-row, and unseen-family findings.
- [ ] Confirm `docs/BASELINE_RESULTS_V2.md` shows no baseline passing all gates and Bot recall near zero.
- [ ] Confirm `docs/SLO_AND_ONCALL.md` reports the latest 20 flows/s p95 of 164.9 ms, the previously measured higher-rate backpressure behavior, and the limits of the local SLO claim.
- [ ] Confirm `docs/THRESHOLD_POLICY_V2.md` reports per-day and per-seed FPR, recall, precision, and alert volume, and documents the threshold-transfer failure.
- [ ] Confirm `docs/CALIBRATION_V2.md` compares uncalibrated, temperature, and isotonic scores with ECE/Brier and states that the serving RF is uncalibrated because the available isotonic artifact fails the ECE gate.
- [ ] Confirm `docs/UNSEEN_FAMILY_AND_BOTNET.md` and `docs/d6_unseen_family_results.json` agree that no D6 arm reaches Bot recall ≥ 0.50 at ≤ 1% FPR and that detection stays 4/10.
- [ ] Confirm `docs/COST_MODEL_AND_RELEASE_GATE.md` and `docs/COST_SENSITIVE_RESULTS.json` agree on the break-even ratios and on the 7-of-9 gate failure with artifact identity passing.
- [ ] Confirm `docs/S7_PILOT_OUTCOME.md` states that no pilot was run and that `docs/s7_pilot_analysis_selftest.json` is labelled `SYNTHETIC SELF-TEST — NOT PILOT EVIDENCE`.
- [ ] Run `venv/Scripts/python.exe scripts/release_gate.py` and confirm the verdict is FAIL with the external review and pilot checks blocked.
- [ ] Confirm `docs/s8_external_review.json` says `not_commissioned` and is not cited as a review result.
- [ ] Confirm `docs/PHASE_STATUS.md` marks D7, D8/S7, S4 external test, and S8 external review as blocked rather than done.
- [ ] Confirm P3 sensor fields are nullable, legacy rows stay unattributed, and `tests/test_sensor_identity.py` proves cross-tenant filter and summary isolation.
- [ ] Confirm `python scripts/deployment_check.py` passes and stored predictions carry model version, artifact hash, feature schema, threshold policy, and calibration version.
- [ ] Confirm `tests/test_migrations.py` runs a real `alembic upgrade head` and that an unversioned database fails the startup guard.
- [ ] Confirm `tests/test_mfa.py` covers RFC 6238 vectors, replay rejection, recovery-code single use, lockout, and fail-closed enrollment.
- [ ] Confirm `tests/test_oidc.py` rejects wrong `state`, `nonce`, audience, issuer, `azp`, algorithm, signature, expiry, and unverified email.
- [ ] Confirm `scripts/preflight.py` fails closed on SQLite, `memory://`, a missing backup key, or placeholder secrets.
- [ ] Confirm `docs/SECURITY_AND_COMPLIANCE.md` and `docs/SECURITY_FINDINGS.json` record the scans, open findings, and blocked external penetration test, and that enterprise readiness is not claimed.
- [ ] Confirm `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` reports 80/80 upload-parser coverage and the ICMP/IPv6 flow-coverage gap.
- [ ] Confirm no page text claims deployment readiness, novel detection, live validation, or a successful human study.
