# DistriNet-Corrected CIC-IDS-2017 Dataset Audit

**Status:** downloaded and inspected locally; used by the P3C strict-policy sensitivity run.
**Rows audited:** 2,099,976
**Files:** 5
**Source:** <https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip>

The corrected release is a different artifact from the original Kaggle
CSV export used by the frozen training protocol. Column names, label
strings, and an extra `Attempted Category` column differ. This audit
records availability and provenance only; it does not change any model,
threshold, or label policy.

## Files

| File | Bytes | Rows | SHA-256 |
| --- | ---: | ---: | --- |
| `friday.csv` | 285,188,226 | 547,557 | `ebd499e6f23bd59f9cb81bec28178491b02b925fa5640a24215c9437d79482d0` |
| `monday.csv` | 207,875,155 | 371,624 | `51fe5dc962626efb4ae70dce0303072fb780da0932822b651202ee9c2fbc1aff` |
| `thursday.csv` | 189,519,159 | 362,076 | `78a4d11eaf473d099e30e71ddb01e0f38218e844c0a9cdd36602145d674af482` |
| `tuesday.csv` | 178,397,720 | 322,078 | `e2a0a5b631dfc6b455cc9f9a88b944110637d70a7f74171473925f76f38b6b0c` |
| `wednesday.csv` | 291,290,505 | 496,641 | `bf46c5f3c792e8817381f724511229569606918eaf07ac986d7a2592b6341bc2` |

## Schema availability

- Tier A: **12/12** columns present after the corrected-name mapping.
- Portable inputs: **4/4** present.

| Tier A feature | Corrected column | Present |
| --- | --- | --- |
| `flow_duration` | `Flow Duration` | yes |
| `total_fwd_packets` | `Total Fwd Packet` | yes |
| `total_backward_packets` | `Total Bwd packets` | yes |
| `total_length_of_fwd_packets` | `Total Length of Fwd Packet` | yes |
| `total_length_of_bwd_packets` | `Total Length of Bwd Packet` | yes |
| `flow_packets_s` | `Flow Packets/s` | yes |
| `flow_bytes_s` | `Flow Bytes/s` | yes |
| `packet_length_mean` | `Packet Length Mean` | yes |
| `packet_length_max` | `Packet Length Max` | yes |
| `syn_flag_count` | `SYN Flag Count` | yes |
| `fin_flag_count` | `FIN Flag Count` | yes |
| `rst_flag_count` | `RST Flag Count` | yes |

## Label counts

| Label | Rows |
| --- | ---: |
| `BENIGN` | 1,582,566 |
| `Botnet` | 736 |
| `Botnet - Attempted` | 4,067 |
| `DDoS` | 95,144 |
| `DoS GoldenEye` | 7,567 |
| `DoS GoldenEye - Attempted` | 80 |
| `DoS Hulk` | 158,468 |
| `DoS Hulk - Attempted` | 581 |
| `DoS Slowhttptest` | 1,740 |
| `DoS Slowhttptest - Attempted` | 3,368 |
| `DoS Slowloris` | 3,859 |
| `DoS Slowloris - Attempted` | 1,847 |
| `FTP-Patator` | 3,972 |
| `FTP-Patator - Attempted` | 12 |
| `Heartbleed` | 11 |
| `Infiltration` | 36 |
| `Infiltration - Attempted` | 45 |
| `Infiltration - Portscan` | 71,767 |
| `Portscan` | 159,066 |
| `SSH-Patator` | 2,961 |
| `SSH-Patator - Attempted` | 27 |
| `Web Attack - Brute Force` | 73 |
| `Web Attack - Brute Force - Attempted` | 1,292 |
| `Web Attack - SQL Injection` | 13 |
| `Web Attack - SQL Injection - Attempted` | 5 |
| `Web Attack - XSS` | 18 |
| `Web Attack - XSS - Attempted` | 655 |

## Provenance

- Citation: Liu, Engelen, Lynar, Essam, Joosen (2022), Error Prevalence in NIDS Datasets: A Case Study on CIC-IDS-2017 and CSE-CIC-IDS-2018, IEEE CNS 2022.
- Licence note: The DistriNet page requires citation. The Kaggle mirror (dhoogla/distrinetcicids2017) lists CC BY-NC-SA 4.0. Verify the current licence before redistributing the CSVs; this repository does not version them.
- Zip SHA-256: `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`

## Limits

- The corrected release uses singular 'Total Fwd Packet'/'Total Bwd packets' names, not the original Kaggle names.
- Label strings differ in case and spelling from the frozen POSITIVE_LABELS set; they require an explicit mapping before any supervised use.
- Attempted Category is a corrected-release column and is not part of the original label policy.
- This audit does not train, score, or tune a model.
- The release is consumed by scripts/corrected_label_sensitivity.py under the strict frozen policy; that is an in-distribution sensitivity (see docs/CORRECTED_LABEL_SENSITIVITY.md), not external validation.

