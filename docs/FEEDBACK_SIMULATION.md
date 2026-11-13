# Simulated Analyst Feedback Experiment (Phase 5)

> [!IMPORTANT]
> **Disclaimers & Experimental Protocol:**
> - This is an **offline retrospective simulation** using time-ordered historical partitions, **NOT a prospective human study**.
> - Assumes instantaneous, 100% accurate ground-truth labeling for selected flows with zero fatigue or delay.
> - Partitions strictly enforce time ordering: Initial Train (Mon-Tue) -> Validation (Wed) -> Review Period (Thu) -> Untouched Evaluation (Fri).
> - **Zero Friday labels or flows** were accessible during Thursday selection or adaptation.

## Experimental Setup
- **Initial Training (Mon-Tue)**: 975,789 flows (BENIGN, FTP-Patator, SSH-Patator)
- **Validation (Wed)**: 692,686 flows (used strictly to freeze the operating threshold at max FPR <= 1%)
- **Review Batch (Thu)**: 458,825 flows (Web Attacks, Infiltration - scored without labels; only budget flows revealed)
- **Untouched Evaluation (Fri)**: 703,240 flows (Bot, PortScan, DDoS)
- **Classifier**: RF | **Seeds**: [42, 43, 44, 45, 46]

## Comparative Results Across Policies & Budgets

| Policy | Budget (B) | Binary PR-AUC | Test Recall @ 1% Val FPR | Test FPR | Alert Rate | Bot Recall | PortScan Recall | DDoS Recall | Precision @ 50/10k |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **No Feedback (Baseline)** | 0 | 0.8561 ± 0.0530 | 0.5805 ± 0.1489 | 0.0061 ± 0.0024 | 0.2421 ± 0.0619 | 0.0094 ± 0.0082 | 0.5642 ± 0.2533 | 0.6095 ± 0.0621 | 0.9753 ± 0.0072 |
| **Random Sampling** | 50 | 0.8083 ± 0.0312 | 0.4513 ± 0.0776 | 0.0072 ± 0.0026 | 0.1896 ± 0.0311 | 0.0072 ± 0.0089 | 0.3201 ± 0.1604 | 0.6209 ± 0.0882 | 0.9767 ± 0.0081 |
| **Top Alert / SOC Triage** | 50 | 0.8467 ± 0.1152 | 0.5889 ± 0.2777 | 0.0110 ± 0.0058 | 0.2485 ± 0.1154 | 0.0122 ± 0.0102 | 0.6243 ± 0.3523 | 0.5539 ± 0.2688 | 0.9736 ± 0.0170 |
| **Uncertainty Sampling** | 50 | 0.8585 ± 0.0500 | 0.6008 ± 0.1324 | 0.0125 ± 0.0054 | 0.2542 ± 0.0536 | 0.0078 ± 0.0057 | 0.5804 ± 0.2402 | 0.6352 ± 0.0036 | 0.9779 ± 0.0107 |
| **Random Sampling** | 100 | 0.8458 ± 0.0556 | 0.5559 ± 0.1600 | 0.0071 ± 0.0038 | 0.2326 ± 0.0679 | 0.0101 ± 0.0090 | 0.5452 ± 0.2756 | 0.5776 ± 0.1330 | 0.9816 ± 0.0076 |
| **Top Alert / SOC Triage** | 100 | 0.8148 ± 0.0814 | 0.4931 ± 0.2129 | 0.0118 ± 0.0053 | 0.2095 ± 0.0858 | 0.0109 ± 0.0106 | 0.5145 ± 0.2746 | 0.4739 ± 0.1733 | 0.9733 ± 0.0108 |
| **Uncertainty Sampling** | 100 | 0.8610 ± 0.0471 | 0.6071 ± 0.1312 | 0.0135 ± 0.0087 | 0.2574 ± 0.0529 | 0.0090 ± 0.0083 | 0.5770 ± 0.2417 | 0.6537 ± 0.0473 | 0.9773 ± 0.0094 |
| **Random Sampling** | 250 | 0.7971 ± 0.0531 | 0.4376 ± 0.1368 | 0.0097 ± 0.0063 | 0.1855 ± 0.0565 | 0.0110 ± 0.0078 | 0.3071 ± 0.1993 | 0.6062 ± 0.1107 | 0.9733 ± 0.0113 |
| **Top Alert / SOC Triage** | 250 | 0.8276 ± 0.0696 | 0.5355 ± 0.1715 | 0.0194 ± 0.0131 | 0.2314 ± 0.0687 | 0.2035 ± 0.1062 | 0.6491 ± 0.3551 | 0.3996 ± 0.1709 | 0.9515 ± 0.0255 |
| **Uncertainty Sampling** | 250 | 0.8343 ± 0.0146 | 0.5294 ± 0.0451 | 0.0131 ± 0.0061 | 0.2252 ± 0.0213 | 0.0093 ± 0.0077 | 0.4787 ± 0.0609 | 0.6002 ± 0.0772 | 0.9771 ± 0.0083 |

## Key Findings and Discussion

1. **Holdout Generalization vs. Review Specificity**:
   - Revealing labels for Thursday attacks (Web Attacks & Infiltration) provides specific examples of those families, but Friday contains completely different families (Bot, PortScan, DDoS).
   - The simulation directly tests whether intermediate feedback helps the model learn invariant attack boundaries or whether it overfits to the review day's specific attack types.

2. **Policy Trade-offs**:
   - **Top Alert / SOC Triage**: Focuses the analyst's budget on flows the current model already considers anomalous. High review precision, but risks confirming existing model biases.
   - **Uncertainty Sampling**: Queries flows near the decision boundary. High value for refining thresholds on borderline benign/malicious traffic.
   - **Random Sampling**: Provides unbiased coverage of background traffic shifts, helping suppress false positives from novel benign protocols.

3. **Threats to Validity**:
   - Real security analysts do not have access to ground-truth PCAP labels; real triage introduces noise, misclassification, and inconclusive tickets.
   - Future work must evaluate active feedback in a live pilot environment with measured human interaction times.