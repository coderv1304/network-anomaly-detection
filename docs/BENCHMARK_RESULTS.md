# Model Baseline Benchmark Results

*Generated on: 2026-10-13 17:10:42 UTC*
*Evaluated across 3 random seeds with 95% confidence / standard deviations.*

## 1. Summary Comparison Table

| Model | Macro-F1 (Mean ± Std) | Weighted-F1 | FPR @ 95% TPR | Train Time (s) | Latency (µs / flow) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | 0.1072 ± 0.0030 | 0.7417 | 0.00% | 2.60s | 21.3 µs |
| **Logistic Regression** | 0.1005 ± 0.0017 | 0.7355 | 0.00% | 2.36s | 4.9 µs |
| **LightGBM** | 0.1177 ± 0.0043 | 0.7460 | 0.00% | 8.96s | 39.6 µs |
| **Isolation Forest (Unsupervised)** | 0.0629 ± 0.0057 | 0.5995 | N/A | 0.66s | 15.7 µs |

## 2. Methodology & Findings
- **Evaluation Discipline:** All models were evaluated inside identical leak-free pipelines with median imputation and scaling fitted strictly on training data.
- **Macro-F1 vs Weighted-F1:** Weighted-F1 appears high because the benign class dominates, whereas Macro-F1 rigorously penalizes misclassifications on rare attack classes (e.g., Infiltration, Heartbleed, SQL Injection).
- **Inference Latency:** Measured on single-core CPU execution to establish empirical baseline before Go capture pipeline integration.