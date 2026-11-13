# Model Baseline Benchmark Results

*Generated on: 2026-11-05 17:39:40 UTC*
*Mean ± sample standard deviation across 3 random seeds; this is not a confidence interval.*
*Data directory: `data\samples`. Split: stratified random row holdout.*
*Seeds: 42, 43, 44.*
*Input SHA-256: `network_test_dataset.csv` `7e0538b1969d5087acfcab4e25fa2259bd031aaee401f829d2ec80f52736ca8b`; `test_dataset.csv` `1aaa522a86da6873670d53fb9ec8d0e1910270d28effcfca79f895c7b6bbd0e0`*

## 1. Summary Comparison Table

| Model | Task | Macro-F1 (Mean ± Std) | Weighted-F1 | Attack PR-AUC | FPR @ 95% TPR | Multiclass Brier | ECE (10 bins) | Train Time (s) | Latency (µs / flow) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | multiclass | 0.1072 ± 0.0037 | 0.7417 | 1.0000 | 0.00% | 0.2619 | 0.0125 | 2.55s | 21.2 µs |
| **Logistic Regression** | multiclass | 0.1004 ± 0.0020 | 0.7354 | 0.9989 | 0.01% | 0.2640 | 0.0132 | 2.61s | 4.3 µs |
| **LightGBM** | multiclass | 0.1177 ± 0.0053 | 0.7460 | 1.0000 | 0.00% | 0.2898 | 0.0733 | 13.64s | 39.4 µs |
| **Isolation Forest (Unsupervised)** | binary | 0.5923 ± 0.1466 | 0.6964 | N/A | N/A | N/A | N/A | 0.69s | 13.8 µs |

## Per-class Results

Precision, recall, F1, support, and PR-AUC are means across seeds. PR-AUC is N/A when the fitted model has no output column for that class.

| Model | Task | Class | Precision | Recall | F1 | Mean support | PR-AUC |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: |
| Random Forest | multiclass | BENIGN | 0.9965 | 1.0000 | 0.9983 | 2861.0 | 1.0000 |
| Random Forest | multiclass | Bot | 0.0601 | 0.0168 | 0.0262 | 119.0 | 0.0957 |
| Random Forest | multiclass | DDoS | 0.2188 | 0.6706 | 0.3300 | 252.0 | 0.2113 |
| Random Forest | multiclass | DoS GoldenEye | 0.0000 | 0.0000 | 0.0000 | 63.0 | 0.0515 |
| Random Forest | multiclass | DoS Hulk | 0.0776 | 0.0122 | 0.0207 | 109.0 | 0.0938 |
| Random Forest | multiclass | DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0473 |
| Random Forest | multiclass | DoS slowloris | 0.0000 | 0.0000 | 0.0000 | 53.0 | 0.0587 |
| Random Forest | multiclass | FTP-Patator | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0537 |
| Random Forest | multiclass | Heartbleed | 0.0000 | 0.0000 | 0.0000 | 14.0 | 0.0116 |
| Random Forest | multiclass | Infiltration | 0.0000 | 0.0000 | 0.0000 | 18.0 | 0.0114 |
| Random Forest | multiclass | PortScan | 0.1879 | 0.3043 | 0.2322 | 207.0 | 0.1803 |
| Random Forest | multiclass | SSH-Patator | 0.0000 | 0.0000 | 0.0000 | 56.0 | 0.0487 |
| Random Forest | multiclass | Web Attack – Brute Force | 0.0000 | 0.0000 | 0.0000 | 87.0 | 0.0693 |
| Random Forest | multiclass | Web Attack – Sql Injection | 0.0000 | 0.0000 | 0.0000 | 32.0 | 0.0376 |
| Random Forest | multiclass | Web Attack – XSS | 0.0000 | 0.0000 | 0.0000 | 54.0 | 0.0469 |
| Logistic Regression | multiclass | BENIGN | 0.9910 | 0.9997 | 0.9953 | 2861.0 | 0.9997 |
| Logistic Regression | multiclass | Bot | 0.1111 | 0.0028 | 0.0055 | 119.0 | 0.0999 |
| Logistic Regression | multiclass | DDoS | 0.2094 | 0.7354 | 0.3259 | 252.0 | 0.2042 |
| Logistic Regression | multiclass | DoS GoldenEye | 0.0000 | 0.0000 | 0.0000 | 63.0 | 0.0536 |
| Logistic Regression | multiclass | DoS Hulk | 0.0000 | 0.0000 | 0.0000 | 109.0 | 0.0898 |
| Logistic Regression | multiclass | DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0461 |
| Logistic Regression | multiclass | DoS slowloris | 0.0000 | 0.0000 | 0.0000 | 53.0 | 0.0458 |
| Logistic Regression | multiclass | FTP-Patator | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0421 |
| Logistic Regression | multiclass | Heartbleed | 0.0000 | 0.0000 | 0.0000 | 14.0 | 0.0116 |
| Logistic Regression | multiclass | Infiltration | 0.0000 | 0.0000 | 0.0000 | 18.0 | 0.0133 |
| Logistic Regression | multiclass | PortScan | 0.1631 | 0.1997 | 0.1795 | 207.0 | 0.1703 |
| Logistic Regression | multiclass | SSH-Patator | 0.0000 | 0.0000 | 0.0000 | 56.0 | 0.0548 |
| Logistic Regression | multiclass | Web Attack – Brute Force | 0.0000 | 0.0000 | 0.0000 | 87.0 | 0.0702 |
| Logistic Regression | multiclass | Web Attack – Sql Injection | 0.0000 | 0.0000 | 0.0000 | 32.0 | 0.0302 |
| Logistic Regression | multiclass | Web Attack – XSS | 0.0000 | 0.0000 | 0.0000 | 54.0 | 0.0464 |
| LightGBM | multiclass | BENIGN | 0.9993 | 0.9999 | 0.9996 | 2861.0 | 1.0000 |
| LightGBM | multiclass | Bot | 0.1276 | 0.0728 | 0.0925 | 119.0 | 0.1138 |
| LightGBM | multiclass | DDoS | 0.2227 | 0.5767 | 0.3213 | 252.0 | 0.2240 |
| LightGBM | multiclass | DoS GoldenEye | 0.0923 | 0.0106 | 0.0186 | 63.0 | 0.0603 |
| LightGBM | multiclass | DoS Hulk | 0.0619 | 0.0275 | 0.0380 | 109.0 | 0.0872 |
| LightGBM | multiclass | DoS Slowhttptest | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0423 |
| LightGBM | multiclass | DoS slowloris | 0.0667 | 0.0063 | 0.0115 | 53.0 | 0.0493 |
| LightGBM | multiclass | FTP-Patator | 0.0000 | 0.0000 | 0.0000 | 55.0 | 0.0433 |
| LightGBM | multiclass | Heartbleed | 0.0000 | 0.0000 | 0.0000 | 14.0 | 0.0105 |
| LightGBM | multiclass | Infiltration | 0.0000 | 0.0000 | 0.0000 | 18.0 | 0.0142 |
| LightGBM | multiclass | PortScan | 0.1910 | 0.3140 | 0.2375 | 207.0 | 0.1827 |
| LightGBM | multiclass | SSH-Patator | 0.0000 | 0.0000 | 0.0000 | 56.0 | 0.0452 |
| LightGBM | multiclass | Web Attack – Brute Force | 0.0661 | 0.0153 | 0.0248 | 87.0 | 0.0745 |
| LightGBM | multiclass | Web Attack – Sql Injection | 0.0000 | 0.0000 | 0.0000 | 32.0 | 0.0355 |
| LightGBM | multiclass | Web Attack – XSS | 0.0893 | 0.0123 | 0.0217 | 54.0 | 0.0496 |
| Isolation Forest (Unsupervised) | binary | ATTACK | 0.5487 | 0.2538 | 0.3434 | 1174.0 | N/A |
| Isolation Forest (Unsupervised) | binary | BENIGN | 0.7576 | 0.9468 | 0.8412 | 2861.0 | N/A |

## 2. Methodology & Findings
- Preprocessing statistics and label vocabularies are fitted on the training partition only.
- Random row splits can put related flows from the same capture days on both sides; these results do not establish temporal or environment generalization.
- Attack PR-AUC scores benign versus any non-benign row; it does not measure which attack family was identified. The per-class table shows the multi-class failure modes.
- Brier score and ECE are uncalibrated test-set diagnostics. No probability calibration method or operational threshold has been selected.
- The Isolation Forest row is a binary benign-versus-anomaly task. Its macro-F1 is not directly comparable to the supervised multi-class rows.
- FPR at 95% TPR is computed from supervised model scores; the Isolation Forest row reports N/A because calibrated probability was not evaluated.
- Latency is batch inference elapsed time divided by test rows on this host; it is not a production throughput guarantee.
