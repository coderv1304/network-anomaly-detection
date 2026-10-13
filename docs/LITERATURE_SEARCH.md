# Problem Statement & Literature Review

## 1. Problem Statement

> **Working Problem Statement:**  
> *"This study investigates the generalization gap and feature-parity discrepancies of machine-learning-based intrusion detection systems trained on synthetic benchmark datasets (CIC-IDS-2017) when evaluated under temporal splits, cross-dataset drift, and real-time live network traffic captured via a low-overhead Go-based flow assembler."*

---

## 2. Search Strategy

- **Databases:** Scopus, Google Scholar, IEEE Xplore, ACM Digital Library.
- **Search Queries:**
  - `"CIC-IDS-2017" AND ("generalization" OR "cross-dataset" OR "label noise")`
  - `"network intrusion detection" AND ("temporal split" OR "time-based split" OR "data leakage")`
  - `"live traffic" AND "machine learning IDS" AND ("feature parity" OR "CICFlowMeter")`
  - `"dos and don'ts" AND "machine learning in cybersecurity"`

---

## 3. Related Work Matrix

| Citation | Year | Focus / Core Contribution | Dataset(s) Evaluated | Split & Evaluation Methodology | Key Findings & Limitations | What's Different in Our Study |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Engelen et al.**<br>*Computers & Security* | 2021 | Critical audit of CIC-IDS-2017; identified pervasive labeling errors and flowmeter bugs. | CIC-IDS-2017 | Code & packet trace audit; flow reconstruction | Discovered incorrect attack timestamps, duplicate flows, and flawed TCP flag handling. | We incorporate these corrected cleaning rules directly into our pipeline and benchmark against them. |
| **Arp et al.**<br>*USENIX Security* | 2022 | "Dos and Don'ts of Machine Learning in Cybersecurity" (Pitfalls in security ML). | Multiple (Android, Network IDS, Malware) | Methodological survey & meta-analysis | Identifies sampling bias, data snooping (scaling on test sets), and lab-vs-real-world distribution shifts. | We explicitly implement leak-free pipelines and measure FPR at operational detection thresholds. |
| **Rosay et al.**<br>*IEEE Access / CyberSec* | 2020 | Cross-dataset evaluation of NIDS models (CIC-IDS-2017 vs. CSE-CIC-IDS2018). | CIC-IDS-2017, CSE-CIC-IDS2018 | Cross-dataset domain transfer | Performance drops dramatically (up to 40% F1 degradation) when evaluating across distinct test beds. | We evaluate both cross-dataset transfer AND live-traffic feature parity with physical packet assembly. |
| **Sommer & Paxson**<br>*IEEE S&P* | 2010 | "Outside the Closed World: On Using Machine Learning for Network Intrusion Detection" | Real enterprise traffic & synthetic traces | Conceptual & empirical analysis | ML models suffer from high false-positive costs, non-stationary traffic, and semantic semantic gaps. | We address feature drift quantitatively via PSI/KS tests and ground-truth lab attacks. |
| **Lanvin et al.**<br>*IEEE EuroS&P Workshop* | 2023 | Evaluating ML-IDS generalization on temporal splits vs. random splits. | CIC-IDS-2017, TON_IoT | Random k-fold vs. Time-based partition | Random splits inflate accuracy by 15–30%; models overfit to session-specific flow artifacts. | We mandate day-based/temporal splits and leave-one-attack-class-out validation. |
| *[Your Scholar Search 1]* | YYYY | *To be filled from Scopus/Scholar query* | | | | |
| *[Your Scholar Search 2]* | YYYY | *To be filled from Scopus/Scholar query* | | | | |
| *[Your Scholar Search 3]* | YYYY | *To be filled from Scopus/Scholar query* | | | | |

---

## 4. Key Takeaways for Project Methodology

1. **Splitting Discipline:** Never evaluate intrusion detection using random row splits when flows from identical sessions span both splits.
2. **Feature Parity is Required:** Software flow assemblers (e.g., custom Go vs. Java CICFlowMeter) must have identical timeout semantics (idle/active timeouts, TCP FIN/RST tracking) or the model's decision boundaries become invalid.
3. **Metric Integrity:** Single overall accuracy percentages hide class imbalance collapse; all evaluations must report macro-F1, per-class PR curves, and false-positive rates at specified detection rates.
