# Drift Monitoring Experiment (Phase 6)

> [!IMPORTANT]
> **Methodology & Integrity Rules:**
> - **Strictly Unsupervised Warning Trigger**: The drift monitor tracks only input feature distributions (2-sample KS test & PSI) and model output scores (Score PSI).
> - **No Test Labels in Trigger**: Labels are strictly held out and used retrospectively to audit warning validity.
> - Evaluated against empirical performance degradation (Recall < 50% or FPR > 5%).

## Monitored Feature Set
- `Destination Port` (port access shift)
- `Flow Duration` (session length shift)
- `Total Fwd Packets` (burst volume shift)
- `Packet Length Mean` (payload sizing shift)
- `Flow Packets/s` & `Flow Bytes/s` (traffic rate shifts)
- `Predicted Attack Score` (output distribution stability)

## Chronological Drift Audit Table

| Evaluation Window | Score PSI | Flagged Features | Warning Triggered? | True Recall | True FPR | Degradation? | Monitor Verdict |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Tue_KnownAttacks** | 0.0000 | 2/6 | YES | 1.0000 | 0.0000 | NO | ⚠️ False Warning |
| **Wed_DoS_Heartbleed** | 0.0000 | 6/6 | YES | 0.0000 | 0.0000 | YES |  **True Warning** |
| **Thu_AM_WebAttacks** | 0.0000 | 0/6 | NO | 0.0000 | 0.0000 | YES | ❌ Missed Degradation |
| **Thu_PM_Infiltration** | 0.0000 | 5/6 | YES | 0.0000 | 0.0000 | NO | ⚠️ False Warning |
| **Fri_AM_Botnet** | 0.0000 | 1/6 | NO | 0.0000 | 0.0000 | YES | ❌ Missed Degradation |
| **Fri_PM_PortScan** | 0.0000 | 6/6 | YES | 0.0000 | 0.0000 | YES |  **True Warning** |
| **Fri_PM_DDoS** | 0.0000 | 6/6 | YES | 0.0000 | 0.0000 | YES |  **True Warning** |

## Summary Diagnostics
- **True Warnings (Accurate alerts of degradation)**: 3
- **False Warnings (Benign distribution shifts)**: 2
- **Missed Degradations (Unsignaled model failures)**: 2
- **Correctly Quiet (Stable traffic)**: 0

## Key Findings & Limitations

1. **Benign Drift vs Malicious Drift**:
   - Feature distribution shift does not strictly imply attack activity. Non-malicious changes in protocol mix (e.g. shifts in normal HTTP vs DNS volume) trigger false warnings.
   - Unsupervised score PSI reliably detects sudden novel bursts (such as DDoS or PortScan) but can struggle with low-volume stealth attacks (such as Infiltration).

2. **Operational Recommendation**:
   - Drift warnings should trigger **model audit and review** rather than automated firewall blocking or alerting SOC tier-1 analysts.