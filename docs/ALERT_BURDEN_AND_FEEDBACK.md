# Phase 4 & Phase 5: Alert Burden and Simulated Analyst Feedback

This document specifies the research design, operational assumptions, and experimental implementation for:
- **Phase 4**: Measuring analyst alert burden under predeclared alert budgets.
- **Phase 5**: Offline simulation of limited analyst feedback across chronologically ordered traffic.

---

## Phase 4: Analyst Alert Burden Evaluation

### 1. Motivation and Operational Context
Traditional machine learning metrics (e.g. AUROC, Macro-F1) assume that all scores or binary classifications are consumed equally. In real Security Operations Centers (SOCs):
- **Analyst triage capacity is strictly finite**: Tier-1 analysts can realistically inspect only 20 to 50 alerts per shift.
- **Threshold-induced alert floods**: Fixed probability thresholds (e.g. $p \ge 0.5$) cause unbounded alert volume during traffic spikes or distribution shifts, overwhelming analysts.
- **Top-$K$ alert queue triage**: Real security monitoring ranks incoming flows by anomaly/threat score and presents analysts with the top-$K$ alerts that fit their available capacity.

### 2. Predeclared Budget Definitions
To maintain evaluation integrity, budgets are declared **prior to examining test results**:

| Budget Type | Specification | Operational Meaning |
|---|---|---|
| **Rate-Based** | 10, 50, 100 alerts per 10,000 flows | Scales with enterprise network traffic volume |
| **Volume-Based** | Fixed 50, 100, 250, 500 alerts | Represents strict fixed-shift analyst review capacity |

### 3. Reported Metrics for Every Budget $K$
For a test partition of $N$ flows:
1. **Precision @ $K$**: $\frac{\text{True Attacks in Top } K}{K}$ (purity of the alert queue).
2. **Recall @ $K$**: $\frac{\text{True Attacks in Top } K}{\text{Total True Attacks}}$ (fraction of all attacks caught within budget).
3. **False Positives per 10,000 Benign Flows**: $\frac{\text{Benign Flows in Top } K}{\text{Total Benign Flows}} \times 10,000$.
4. **Per-Family Recall @ $K$**: For each attack family $f$, the proportion of its flows captured in the top-$K$ alerts.
5. **Effective Score Threshold**: The score of the $K$-th ranked flow.

These results are computed alongside frozen-threshold metrics and recorded in both machine-readable JSON manifests and aggregated summary tables.

---

## Phase 5: Limited Analyst Feedback Simulation

### 1. Research Question
Does a small, realistic review budget during an intermediate operational period allow an intrusion detection model to adapt and improve detection quality or reduce alert burden on a subsequent, untouched period?

### 2. Time-Ordered Partitions & Leak-Free Separation
To preserve causal realism, the CIC-IDS-2017 dataset is partitioned chronologically into four non-overlapping stages:

```
[Monday - Tuesday]  -->  [Wednesday]  -->  [Thursday]          -->  [Friday]
Initial Training         Validation        Review Period             Untouched Evaluation
(BENIGN, FTP, SSH)       (Threshold Freeze) (Web Attacks, Infilt)     (Bot, PortScan, DDoS)
                                           Labels hidden until       Zero Friday data seen
                                           budget selection          until final evaluation
```

- **Initial Training (Mon–Tue)**: Historical training traffic (975,789 flows).
- **Validation (Wed)**: Used strictly to freeze the baseline operating threshold at validation $\text{FPR} \le 1\%$.
- **Review Period (Thu)**: Intermediate production traffic (458,968 flows). The model scores these flows without access to their labels.
- **Untouched Evaluation (Fri)**: Held-out future traffic (703,097 flows) containing unseen attack families (Bot, PortScan, DDoS).

### 3. Selection Policies under Budget $B$
Under fixed labeling budgets $B \in \{50, 100, 250, 500\}$ flows from the Thursday review batch:

1. **No-Feedback Baseline ($B = 0$)**:
   The initial model (trained on Mon–Tue) is deployed directly to Friday without any review or updates.
2. **Random Sampling (`random`)**:
   Analyst audits a uniform random sample of $B$ flows from Thursday.
3. **Top Alert / SOC Triage (`top_alert`)**:
   Analyst reviews the top $B$ highest anomaly/attack scores ($1 - P(\text{BENIGN})$). Mirrors standard tier-1 priority queue triage.
4. **Uncertainty Sampling (`uncertainty`)**:
   Analyst reviews the $B$ flows closest to the decision threshold ($|s_i - \text{threshold}|$ minimized). Mirrors active learning.

### 4. Documented Retraining Policy
- Only the selected $B$ flows have their true labels revealed.
- The training set is augmented: $\mathcal{D}_{\text{adapted}} = \mathcal{D}_{\text{train}} \cup \mathcal{D}_{\text{feedback}}$.
- Feedback flows are balanced with sample weighting so the rare newly discovered attack samples are not drowned out by historical flows.
- The unified preprocessing and modeling pipeline is retrained strictly on $\mathcal{D}_{\text{adapted}}$.
- **Integrity Check**: Friday data and labels are never seen during selection or adaptation.

### 5. Essential Disclaimers & Threats to Validity
> [!WARNING]
> **Simulated Feedback vs. Human Studies**:
> - This experiment is an **offline retrospective simulation**, NOT a prospective human study.
> - **Assumptions**: Labels provided by the simulated analyst are assumed to be 100% accurate, instantaneous, and free of cognitive fatigue. In real security operations, analyst investigations frequently involve ambiguous telemetry, label noise, and triage backlogs.
> - **Holdout Attack Diversity**: The simulation tests whether adaptation to Thursday attacks (Web Attacks, Infiltration) yields features that generalize to Friday attacks (Bot, PortScan, DDoS), or whether models overfit to the reviewed attacks.

