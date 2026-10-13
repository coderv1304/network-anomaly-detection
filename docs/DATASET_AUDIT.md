# CIC-IDS-2017 Dataset Audit Report

*Generated on: 2026-10-13 16:54:00 UTC*

## 1. Overview & Context
This audit verifies data hygiene and known artifact flaws documented by **Engelen et al. (2021)** in *Computers & Security*. It checks for duplicate flows, infinite values, invalid flow durations, and label anomalies.

## 2. Summary Table

| File | Total Rows | Duplicates (%) | Rows with Inf | Rows with NaN | Zero/Neg Duration |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `network_test_dataset.csv` | 15,000 | 0 (0.0%) | 189 | 179 | 0 |
| `test_dataset.csv` | 5,204 | 32 (0.6%) | 14 | 1 | 14 |

## 3. Label Breakdown per File

### `network_test_dataset.csv`
| Label | Count | Proportion |
| :--- | :--- | :--- |
| **BENIGN** | 9,136 | 60.91% |
| **DDoS** | 1,260 | 8.40% |
| **PortScan** | 1,032 | 6.88% |
| **Bot** | 593 | 3.95% |
| **DoS Hulk** | 543 | 3.62% |
| **Web Attack – Brute Force** | 434 | 2.89% |
| **DoS GoldenEye** | 314 | 2.09% |
| **SSH-Patator** | 280 | 1.87% |
| **DoS Slowhttptest** | 275 | 1.83% |
| **FTP-Patator** | 274 | 1.83% |
| **Web Attack – XSS** | 272 | 1.81% |
| **DoS slowloris** | 264 | 1.76% |
| **Web Attack – Sql Injection** | 162 | 1.08% |
| **Infiltration** | 91 | 0.61% |
| **Heartbleed** | 70 | 0.47% |

### `test_dataset.csv`
| Label | Count | Proportion |
| :--- | :--- | :--- |
| **BENIGN** | 5,200 | 99.92% |
| **PortScan** | 4 | 0.08% |

## 4. Pipeline Cleaning Decisions
Based on this audit, our training pipeline enforces the following explicit rules:
1. **Deduplication:** Duplicate flow records must be removed; training on identical flows leads to artificially inflated validation metrics.
2. **Finite Value Imputation:** Infinite values (`Flow Bytes/s`, `Flow Packets/s`) are converted to NaN and imputed using median statistics computed **strictly on the training fold**.
3. **Zero-Duration Filtering:** Flows with negative durations are discarded as sensor artifacts.
4. **Identifier Stripping:** IP addresses, timestamps, and flow IDs are stripped to prevent models from learning host-identity shortcuts.