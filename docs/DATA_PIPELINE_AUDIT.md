# Data, Label, Feature, and Split Audit (Phase D2)

*Generated: 2026-11-08T03:18:02.858335+00:00*
*Data directory: `C:\Users\varun\OneDrive\Desktop\network-anomaly-detection\data`*

## 1. Split rule

| Partition | Source files |
| --- | --- |
| train | `Monday-WorkingHours.pcap_ISCX.csv`, `Tuesday-WorkingHours.pcap_ISCX.csv` |
| validation | `Wednesday-workingHours.pcap_ISCX.csv` |
| test | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`, `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`, `Friday-WorkingHours-Morning.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`, `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` |

## 2. Source files

| File | Rows | Encoding | SHA-256 | Size (MiB) |
| --- | ---: | --- | --- | ---: |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 225,745 | utf-8-sig | `1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4` | 91.6 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 286,467 | utf-8-sig | `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08` | 97.2 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 191,033 | utf-8-sig | `c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21` | 71.9 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 529,918 | utf-8-sig | `96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820` | 256.2 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 288,602 | utf-8-sig | `d74238e054023c8bd4d8056650463cadb25c100fb0e26ebd4272c07b5c022c4b` | 103.7 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 458,968 | cp1252 | `e3deaff483d18b53b100a441dff9b8919416df8876b4edcc0f0d1e4bf48397d0` | 87.8 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 445,909 | utf-8-sig | `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815` | 166.6 |
| `Wednesday-workingHours.pcap_ISCX.csv` | 692,703 | utf-8-sig | `ed538e85b84181e8897dedb3d37d365982f44b27eccd67c477581a8b65f3d170` | 272.4 |

## 3. Class distribution per partition

| Partition | Valid rows | Missing labels | Families |
| --- | ---: | ---: | ---: |
| train | 975,827 | 0 | 3 |
| validation | 692,703 | 0 | 6 |
| test | 1,162,213 | 288,602 | 8 |

### Train label counts

| Canonical label | Rows |
| --- | ---: |
| BENIGN | 961,992 |
| FTP-Patator | 7,938 |
| SSH-Patator | 5,897 |

### Validation label counts

| Canonical label | Rows |
| --- | ---: |
| BENIGN | 440,031 |
| DoS Hulk | 231,073 |
| DoS GoldenEye | 10,293 |
| DoS slowloris | 5,796 |
| DoS Slowhttptest | 5,499 |
| Heartbleed | 11 |

Unseen families (present here, absent from training):

| Family | Rows |
| --- | ---: |
| DoS Hulk | 231,073 |
| DoS GoldenEye | 10,293 |
| DoS slowloris | 5,796 |
| DoS Slowhttptest | 5,499 |
| Heartbleed | 11 |

### Test label counts

| Canonical label | Rows |
| --- | ---: |
| BENIGN | 871,074 |
| PortScan | 158,930 |
| DDoS | 128,027 |
| Bot | 1,966 |
| Web Attack - Brute Force | 1,507 |
| Web Attack - XSS | 652 |
| Infiltration | 36 |
| Web Attack - Sql Injection | 21 |

Unseen families (present here, absent from training):

| Family | Rows |
| --- | ---: |
| PortScan | 158,930 |
| DDoS | 128,027 |
| Bot | 1,966 |
| Web Attack - Brute Force | 1,507 |
| Web Attack - XSS | 652 |
| Infiltration | 36 |
| Web Attack - Sql Injection | 21 |

## 4. Missing and infinite values

| File | Rows with NaN | Rows with Inf | Negative duration | Zero duration |
| --- | ---: | ---: | ---: | ---: |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 4 | 34 | 2 | 34 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 15 | 371 | 36 | 371 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 28 | 122 | 9 | 122 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 64 | 437 | 15 | 437 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 18 | 207 | 4 | 207 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 288,622 | 135 | 11 | 135 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 201 | 264 | 17 | 264 |
| `Wednesday-workingHours.pcap_ISCX.csv` | 1,008 | 1,297 | 21 | 1,297 |

## 5. Duplicates and leakage

| File | Duplicate feature rows |
| --- | ---: |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 126 |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 243 |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 528 |
| `Monday-WorkingHours.pcap_ISCX.csv` | 1,406 |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 566 |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 289,028 |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 1,238 |
| `Wednesday-workingHours.pcap_ISCX.csv` | 8,823 |

| Source partition | Target partition | Overlapping target rows | % of target |
| --- | --- | ---: | ---: |
| train | validation | 1,355 | 0.196% |
| train | test | 1,776 | 0.122% |
| validation | train | 1,277 | 0.131% |
| validation | test | 1,948 | 0.134% |
| test | train | 1,433 | 0.147% |
| test | validation | 1,695 | 0.245% |

## 6. Feature-name consistency

Reference file: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (85 columns).

Physical CSV headers contain duplicate names (pandas appends a numeric suffix on read):

- `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`: `Fwd Header Length`
- `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`: `Fwd Header Length`
- `Friday-WorkingHours-Morning.pcap_ISCX.csv`: `Fwd Header Length`
- `Monday-WorkingHours.pcap_ISCX.csv`: `Fwd Header Length`
- `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`: `Fwd Header Length`
- `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`: `Fwd Header Length`
- `Tuesday-WorkingHours.pcap_ISCX.csv`: `Fwd Header Length`
- `Wednesday-workingHours.pcap_ISCX.csv`: `Fwd Header Length`

All source files expose the same stripped column names in the same order.

## 7. Confirmed defects

| Severity | Area | File | Finding |
| --- | --- | --- | --- |
| high | feature_names | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 34 rows contain infinite feature values. |
| medium | features | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 2 rows have a negative Flow Duration. |
| high | feature_names | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 371 rows contain infinite feature values. |
| medium | features | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 36 rows have a negative Flow Duration. |
| high | feature_names | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 122 rows contain infinite feature values. |
| medium | features | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 9 rows have a negative Flow Duration. |
| high | feature_names | `Monday-WorkingHours.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Monday-WorkingHours.pcap_ISCX.csv` | 437 rows contain infinite feature values. |
| medium | features | `Monday-WorkingHours.pcap_ISCX.csv` | 15 rows have a negative Flow Duration. |
| high | feature_names | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 207 rows contain infinite feature values. |
| medium | features | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 4 rows have a negative Flow Duration. |
| high | feature_names | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | labels | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 288,602 rows have a missing label and are silently dropped by dropna(subset=['Label']). |
| medium | features | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 135 rows contain infinite feature values. |
| medium | features | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 11 rows have a negative Flow Duration. |
| high | feature_names | `Tuesday-WorkingHours.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Tuesday-WorkingHours.pcap_ISCX.csv` | 264 rows contain infinite feature values. |
| medium | features | `Tuesday-WorkingHours.pcap_ISCX.csv` | 17 rows have a negative Flow Duration. |
| high | feature_names | `Wednesday-workingHours.pcap_ISCX.csv` | Duplicate physical CSV header(s) Fwd Header Length; pandas silently renames the later copy with a numeric suffix (for example 'Fwd Header Length.1'), so the two columns are indistinguishable in meaning but separate in the feature schema. |
| medium | features | `Wednesday-workingHours.pcap_ISCX.csv` | 1,297 rows contain infinite feature values. |
| medium | features | `Wednesday-workingHours.pcap_ISCX.csv` | 21 rows have a negative Flow Duration. |
| high | split_leakage | `-` | 1,355 rows in validation duplicate a feature vector in train (0.196% of the target partition). |
| high | split_leakage | `-` | 1,776 rows in test duplicate a feature vector in train (0.122% of the target partition). |
| high | split_leakage | `-` | 1,277 rows in train duplicate a feature vector in validation (0.131% of the target partition). |
| high | split_leakage | `-` | 1,948 rows in test duplicate a feature vector in validation (0.134% of the target partition). |
| high | split_leakage | `-` | 1,433 rows in train duplicate a feature vector in test (0.147% of the target partition). |
| high | split_leakage | `-` | 1,695 rows in validation duplicate a feature vector in test (0.245% of the target partition). |

## 8. Preprocessing configuration

| Setting | Value |
| --- | --- |
| label_vocabulary | fit on training partition only |
| imputer | SimpleImputer(strategy='median') fit on training partition only |
| scaler | StandardScaler fit on training partition only |
| infinity_handling | FlowSanitizer replaces +/-inf with NaN before imputation |
| deduplication | within each partition only (day_based loader) |
| feature_order | first training file order, identifiers removed |

## 9. Reproduce

```bash
venv/Scripts/python.exe training/audit_pipeline_v2.py --data-dir data --output-dir docs
```
