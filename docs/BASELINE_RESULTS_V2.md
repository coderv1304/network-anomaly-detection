# Controlled Baseline Comparison Under the Frozen Protocol (Phase D3)

*Generated: 2026-11-08T03:21:08.509771+00:00*

## 1. Scope and rules

- Split: train = Monday + Tuesday, validation = Wednesday, final test = Thursday + Friday.
- Threshold: selected on validation only by maximising attack recall subject to validation FPR <= 1%, then frozen before test.
- Seeds: 42, 43, 44, 45, 46. Variation across seeds on one fixed split is estimator variation, not independent replication.
- No model is selected using weighted F1 or accuracy. Model rows come from the frozen per-seed artifacts; rule rows are recomputed directly from the final-test partition.
- Per-family precision is not available from the frozen binary attack-flag artifacts. Only per-family recall and support are reported; this is a known gap.

## 2. Provenance

- Data combined SHA-256: `b2d4571a58fe8d77778fa1d7e0d2a1a85fa392ebd12c62dba6d7fa53f86d0bd8`
- Data hashes identical across all runs: `True`
- Feature schema SHA-256: `45cd75ce849b005c854ef8190a1cbe14d0d1a22daa6aa10e05e767ec6a757be6`
- Evaluation protocol SHA-256: `3653986d104dfe3544a98a49b9c86e74622ad54f83e54f79b736e1572bc22de1`
- Rows: train 975,789, validation 692,686, test 1,162,065

| Model | Configuration hash | Artifact hashes (seed: SHA-256) |
| --- | --- | --- |
| Random Forest (multiclass) | `1980538917041bb0c20a1966e66a8eca57bb32b6dafd0a32d4b8145693cf7b90` | 42: `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`<br>43: `25800da4d1cf3899babd3c65fe6b9dc1f5e6a2cac1e8cdce54fc9b9c9b8154ab`<br>44: `4246d17268a763ce37b21147a0436cc1801f9d7a1c4a476f0c1f1150d6909328`<br>45: `4cfe17e605d80e0d5ee6b1d7e9012a10509d344b6a409ff10f9406548c2c2cec`<br>46: `7c0fcb6c4af55647aaf82067a1caa87bf0db6a3f720d1c480dcba5eaf859dee0` |
| Logistic Regression (multiclass) | `472fdafa22322ac5f861d898d749632ecdeae3eb3c8d5a026493a7379e4d45af` | 42: `bf6033cc5186eb4cde6aaf94a8257224528cc68375ab21be574df90ffcf53b86`<br>43: `2bce47cdb85b7fa0567e710e1e3ec87f9b135a2c7f443f6fd4d281fb6bdeb487`<br>44: `b555f76427d742d6b8dc48446b0c3d97c1902b7b73319637f3eab26cc62c2e0e`<br>45: `4612bbd9614f74f517ddafd02dd8b2b600b5db6ee9ae628a3f549145337d201e`<br>46: `f6d3a5c1e90008bf3ba8789591c46067d4b59f0523328f745aa536a8d0d2925d` |
| Isolation Forest (binary anomaly) | `25ff3945992c39a7470661c6c8082daff36cbdafc4a003d093887834f7162c90` | 42: `bccfaae48dbb74897f2261b8123a7a1494d79823ead1dc266d52d987a49426b5`<br>43: `6b5ec3b5440ed1b15b56110c5a895f2b7ac683956b5bf5cd9dec2437a2fbca53`<br>44: `9a17613fa651cbed0b3165293e4e82987495d18ace356e2078033a96b8384d37`<br>45: `1501b7cac1c5ea37c57db407a29290fdcbcd206d720f6cfc2104bb7a18579d6f`<br>46: `2cf1961548e0edc0189db65664549d0715eab1312448e0fefcdcbc41e9e18728` |

## 3. Aggregate results (mean ± sample std across seeds 42-46)

| Method | PR-AUC | ROC-AUC | Frozen threshold | Test FPR | Recall | Precision | Alert rate | Alerts / 10k benign | Brier | ECE | Fit (s) | Inference (ms/flow) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest (multiclass) | 0.7472 ± 0.0749 | 0.7722 ± 0.0742 | 0.006171 ± 0.003800 | 4.11% ± 3.27% | 58.30% ± 14.79% | 83.67% ± 11.64% | 17.68% ± 5.12% | 2359.4 ± 683.8 | 0.4937 ± 0.0030 | 0.2462 ± 0.0020 | 65.70 ± 5.22 | 0.0080 ± 0.0012 |
| Logistic Regression (multiclass) | 0.4306 ± 0.0000 | 0.7001 ± 0.0000 | 0.134543 ± 0.000000 | 2.66% ± 0.00% | 3.52% ± 0.00% | 30.65% ± 0.00% | 2.88% ± 0.00% | 384.1 ± 0.0 | 0.5037 ± 0.0000 | 0.2457 ± 0.0000 | 66.11 ± 5.33 | 0.0071 ± 0.0005 |
| Isolation Forest (binary anomaly) | 0.3523 ± 0.0129 | 0.6758 ± 0.0268 | 0.183018 ± 0.007333 | 1.16% ± 0.03% | 0.46% ± 0.91% | 8.65% ± 16.20% | 0.99% ± 0.23% | 131.7 ± 30.6 | n/a | n/a | 3.38 ± 0.18 | n/a |
| Majority class | 0.2505 | 0.5000 | 0.50 | 0.00% | 0.00% | n/a | 0.00% | 0.0 | 0.2505 | 0.2505 | 0.0017 | n/a |
| Port memorisation (21/22) | 0.2502 | 0.4971 | 0.50 | 0.75% | 0.17% | 6.90% | 0.61% | 75.5 | 0.2557 | 0.2557 | 0.0005 | n/a |
| Ephemeral destination heuristic | 0.3127 | 0.6082 | 0.50 | 25.09% | 46.72% | 38.36% | 30.51% | 2508.7 | 0.3215 | 0.3215 | 0.0009 | n/a |

## 4. Per-family recall at the frozen threshold

Mean ± sample std across seeds for learned models; point estimate for rules. Support is the final-test count.

| Family | Support | Random Forest (multiclass) | Logistic Regression (multiclass) | Isolation Forest (binary anomaly) | Majority class | Port memorisation (21/22) | Ephemeral destination heuristic |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| PortScan | 158,930 | 56.42% ± 25.33% | 6.38% ± 0.00% | 0.00% ± 0.00% | 0.00% | 0.31% | 84.35% |
| DDoS | 128,027 | 60.95% ± 6.21% | 0.01% ± 0.00% | 1.04% ± 2.07% | 0.00% | 0.00% | 0.00% |
| Bot | 1,966 | 0.94% ± 0.82% | 0.00% ± 0.00% | 0.00% ± 0.00% | 0.00% | 0.00% | 100.00% |
| Web Attack - Brute Force | 1,507 | 92.14% ± 2.21% | 5.64% ± 0.00% | 0.00% ± 0.00% | 0.00% | 0.00% | 0.00% |
| Web Attack - XSS | 652 | 94.33% ± 0.91% | 0.92% ± 0.00% | 0.03% ± 0.07% | 0.00% | 0.00% | 0.00% |
| Infiltration | 36 | 36.67% ± 11.69% | 5.56% ± 0.00% | 19.44% ± 5.20% | 0.00% | 0.00% | 0.00% |
| Web Attack - Sql Injection | 21 | 39.05% ± 6.21% | 42.86% ± 0.00% | 0.00% ± 0.00% | 0.00% | 0.00% | 0.00% |

## 5. Gate results

| Method | Bot recall (target >= 0.70) | Botnet gate | Max seed FPR (target <= 1%) | FPR gate | Max alert rate (target <= 2%) | Alert-rate gate | ECE (target <= 0.05) | Calibration gate |
| --- | ---: | :---: | ---: | :---: | ---: | :---: | ---: | :---: |
| Random Forest (multiclass) | 0.94% | FAIL | 7.85% | FAIL | 26.72% | FAIL | 0.2462 | FAIL |
| Logistic Regression (multiclass) | 0.00% | FAIL | 2.66% | FAIL | 2.88% | FAIL | 0.2457 | FAIL |
| Isolation Forest (binary anomaly) | 0.00% | FAIL | 1.21% | FAIL | 1.39% | PASS | n/a | FAIL |
| Majority class | 0.00% | FAIL | 0.00% | PASS | 0.00% | PASS | 0.2505 | FAIL |
| Port memorisation (21/22) | 0.00% | FAIL | 0.75% | PASS | 0.61% | PASS | 0.2557 | FAIL |
| Ephemeral destination heuristic | 100.00% | PASS | 25.09% | FAIL | 30.51% | FAIL | 0.3215 | FAIL |

## 6. Rule baseline definitions

- **Majority class**: Always predict BENIGN. This is the trivial reference for class imbalance.
- **Port memorisation (21/22)**: Flag a flow when its destination port is one of the attack ports seen in the training partition (FTP 21, SSH 22). Uses no test labels.
- **Ephemeral destination heuristic**: Flag a flow when its destination port is above 1023. This is a crude anomaly heuristic: server-side attacks are expected to target well-known service ports.

## 7. Per-seed results for learned models

| Model | Seed | PR-AUC | ROC-AUC | Threshold | Test FPR | Recall | Precision | Alert rate | Bot recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Random Forest (multiclass) | 42 | 0.7900 | 0.7816 | 0.002515 | 0.73% | 57.94% | 96.39% | 15.06% | 1.12% |
| Random Forest (multiclass) | 43 | 0.7827 | 0.7728 | 0.001855 | 0.99% | 56.10% | 94.97% | 14.80% | 0.31% |
| Random Forest (multiclass) | 44 | 0.6452 | 0.7025 | 0.009364 | 6.90% | 46.78% | 69.40% | 16.89% | 0.05% |
| Random Forest (multiclass) | 45 | 0.8249 | 0.8896 | 0.010000 | 7.85% | 83.19% | 77.99% | 26.72% | 1.07% |
| Random Forest (multiclass) | 46 | 0.6932 | 0.7146 | 0.007121 | 4.07% | 47.48% | 79.59% | 14.95% | 2.14% |
| Logistic Regression (multiclass) | 42 | 0.4306 | 0.7001 | 0.134543 | 2.66% | 3.52% | 30.65% | 2.88% | 0.00% |
| Logistic Regression (multiclass) | 43 | 0.4306 | 0.7001 | 0.134543 | 2.66% | 3.52% | 30.65% | 2.88% | 0.00% |
| Logistic Regression (multiclass) | 44 | 0.4306 | 0.7001 | 0.134543 | 2.66% | 3.52% | 30.65% | 2.88% | 0.00% |
| Logistic Regression (multiclass) | 45 | 0.4306 | 0.7001 | 0.134543 | 2.66% | 3.52% | 30.65% | 2.88% | 0.00% |
| Logistic Regression (multiclass) | 46 | 0.4306 | 0.7001 | 0.134543 | 2.66% | 3.52% | 30.65% | 2.88% | 0.00% |
| Isolation Forest (binary anomaly) | 42 | 0.3437 | 0.6517 | 0.176525 | 1.17% | 2.08% | 37.30% | 1.39% | 0.00% |
| Isolation Forest (binary anomaly) | 43 | 0.3664 | 0.6985 | 0.179439 | 1.15% | 0.00% | 0.10% | 0.86% | 0.00% |
| Isolation Forest (binary anomaly) | 44 | 0.3472 | 0.6769 | 0.188703 | 1.14% | 0.00% | 0.08% | 0.86% | 0.00% |
| Isolation Forest (binary anomaly) | 45 | 0.3386 | 0.6462 | 0.177525 | 1.15% | 0.21% | 5.73% | 0.91% | 0.00% |
| Isolation Forest (binary anomaly) | 46 | 0.3658 | 0.7057 | 0.192899 | 1.21% | 0.00% | 0.07% | 0.91% | 0.00% |

## 8. Interpretation

- The Random Forest is the strongest learned baseline on PR-AUC, but its frozen-threshold FPR varies from below 1% to roughly 7.8% across seeds, so it fails the cross-cutting FPR gate on at least one seed.
- Every learned model fails the Botnet recall gate: Bot recall is near zero for Logistic Regression and Isolation Forest and about 1% for the Random Forest.
- The majority baseline fails the Botnet gate and has no ranking ability.
- The port-memorisation rule fails the Botnet gate because the final-test attacks do not reuse the FTP/SSH training ports.
- The ephemeral-destination rule reaches high Bot recall by flagging every Bot flow, but it also flags roughly a quarter of benign flows. It therefore fails the FPR and alert-rate gates. This shows why the Botnet gate must never be evaluated alone.
- Calibration is poor for every learned model (ECE about 0.24-0.25), far above the 0.05 target.
- No baseline passes all predeclared gates. The 9/10 detection claim remains unsupported.

## 9. Reproduce

```bash
venv/Scripts/python.exe training/baseline_comparison_v2.py
```
