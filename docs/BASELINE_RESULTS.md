# Controlled Baseline Comparison (Day-Based Split)

Evaluation across 5 random seeds (42-46) following the frozen evaluation protocol.
Split rule: Train = Monday-Tuesday, Validation = Wednesday (threshold freeze at max FPR <= 1%), Test = Thursday-Friday.

| Baseline Model | Macro-F1 | Weighted-F1 | Binary PR-AUC | Binary ROC-AUC | Test Recall @ 1% Val FPR | Test FPR | Alert Rate | Fit Time (s) |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Random Forest** | 0.0857 ± 0.0000 | 0.6421 ± 0.0000 | 0.7472 ± 0.0749 | 0.7722 ± 0.0742 | 0.5830 ± 0.1479 | 0.0411 ± 0.0327 | 0.1768 ± 0.0512 | 65.7 ± 5.2 |
| **Logistic Regression** | 0.0853 ± 0.0000 | 0.6396 ± 0.0000 | 0.4306 ± 0.0000 | 0.7001 ± 0.0000 | 0.0352 ± 0.0000 | 0.0266 ± 0.0000 | 0.0288 ± 0.0000 | 66.1 ± 5.3 |
| **Isolation Forest** | N/A | N/A | 0.3523 ± 0.0129 | 0.6758 ± 0.0268 | 0.0046 ± 0.0091 | 0.0116 ± 0.0003 | 0.0099 ± 0.0023 | 3.4 ± 0.2 |

### Key Observations
- **Class Imbalance & Unseen Families**: Multiclass models evaluate with low Macro-F1 because test-only attack families (e.g. DDoS, PortScan, Web Attacks) have zero training examples in the temporal split.
- **Frozen Threshold Operating Point**: Thresholds are frozen on Wednesday validation traffic strictly at max FPR <= 0.01 before evaluating on Thursday-Friday traffic.
