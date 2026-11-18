# Scope and Claims Statement (Phase D0)

**Status:** frozen for the current serving artifact and evaluation evidence.
**Date:** 2026-11-12 (artifact identity, ingest SLO, alert-budget reporting, and encrypted backup drill updated).
**Owner:** NetShield maintainers.
**Rule:** if this document and the running application disagree, the application is wrong until the disagreement is fixed or the claim is withdrawn.

## Frozen scope (P0)

> Flow-based detector for volumetric and scanning behavior. Not a general NIDS. Live accuracy is unvalidated. Botnet, web attacks, infiltration, zero-day, and blocking are out of scope.

This supersedes any broader framing elsewhere in the repository. The claim-to-artifact mapping lives in [`CLAIM_EVIDENCE_MATRIX.md`](CLAIM_EVIDENCE_MATRIX.md). Volumetric behavior means flood and high-rate flow patterns; scanning behavior means connection-attempt and destination-fan-out patterns. Neither claim is validated on live traffic.

## One-sentence scope

NetShield is a network-flow research prototype that accepts flow records or packet captures, applies a locally loaded classification artifact, stores the predicted label, and presents the result for human review. It is not a validated live sensor, a threat-intelligence product, or a production detection service.

## Inputs

### Batch and API inputs

- CIC-IDS-style flow CSV rows.
- PCAP and PCAPNG files, dissected into flows by `pcap_parser.py`.
- JSON flow records posted to `POST /api/flows` by a collector or the experimental local capture path.
- Optional collector identity fields `sensor_id` and `interface`. They are stored as metadata, not used as model features, and remain null when the collector does not send them.

### Model feature schema

- The serving artifact declares **80 statistical flow features**.
- Feature names come from the artifact itself (`feature_names`), not from an aspirational schema in the README.
- Labels, IP addresses, ports, and timestamps are not model features unless the artifact explicitly lists them.

### Live-capture feature status

The current live path is **not feature-equivalent** to the training pipeline. The two extraction paths fail differently:

| Item | Current value |
| --- | ---: |
| Required features | 80 |
| PyFlowMeter live path: schema names mapped | 80 |
| PyFlowMeter live path: fixture flows vs upload reference | 4 vs 6 |
| Live-path reference-only flows (ICMP, IPv6) | 2 |
| Scapy upload parser: features produced | 57 |
| Scapy upload parser: missing features | 23 |
| Scapy upload parser: dummy constants | 6 |

The parity report `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` and the application's research context record the remaining live-path gaps: ICMP/IPv6 coverage, numeric disagreement between extractors, and no CICFlowMeter ground truth. The upload path now covers all 80 features. A prediction made from the live path is a prototype output, not a validated live detection. The older `docs/FEATURE_PARITY_LIVE_CAPTURE.md` covers the Scapy upload parser against a reference CSV; it is not evidence about the PyFlowMeter live path.

## Outputs

### Serving label space

`models/model_bundle_rf_day_based_seed42.pkl` is a **three-class Random Forest** with these classes:

- `BENIGN`
- `FTP-Patator`
- `SSH-Patator`

The registry-active serving version `serving-rf-day-based-seed42-v1` has SHA-256 `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350`, identical to the evaluated seed 42 manifest. The serving path applies the attack-score threshold `1 - P(BENIGN) >= 0.002515048908954043` and keeps the raw argmax label for audit. The serving artifact is registered as uncalibrated, so the UI must not present a serving label as calibrated confidence, and must not present it as a confirmed attack.

### Evaluation label space

The evaluated artifact is the same Random Forest seed 42 bundle that is served. Its multiclass vocabulary is limited to the classes present in training. The research reports additionally measure **unseen-family attack flagging** for test families that were absent from training:

- Bot
- DDoS
- Infiltration
- PortScan
- Web Attack – Brute Force
- Web Attack – SQL Injection
- Web Attack – XSS

An unseen-family flag means "the binary attack score crossed a threshold." It does not mean the model identified the family.

## Serving artifact vs evaluation artifact

| Item | Serving artifact | Evaluation artifact |
| --- | --- | --- |
| Registry version | `serving-rf-day-based-seed42-v1` | `rf-day-based-seed42-v1` (research) |
| File | `models/model_bundle_rf_day_based_seed42.pkl` | `models/model_bundle_rf_day_based_seed42.pkl` |
| SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| Algorithm | Random Forest | Random Forest |
| Classes | `BENIGN`, `FTP-Patator`, `SSH-Patator` | Training classes plus separate unseen-family scoring |
| Decision rule | Attack-score threshold `1 - P(BENIGN) >= 0.002515048908954043`; argmax retained for audit | Validation-selected attack threshold in the research report |
| Threshold applied at serving time | Yes | Yes, in the evaluation report |
| Feature count | 80 | 80 |

**Consequence:** a prediction from the running console and the aggregate RF evaluation now describe the same bytes and the same decision rule. The registry and deployment gate enforce hash and feature-schema identity. This fixes artifact provenance; it does not make the detector accurate, calibrated, or externally validated.

## Threshold policy

- The research threshold is selected on the **validation period only**, under a validation false-positive-rate budget of at most **1%**, by maximizing attack recall subject to that budget.
- The selected threshold is frozen before the final test period is scored.
- The serving application applies the same threshold recorded in the registry-active Random Forest bundle (`1 - P(BENIGN) >= 0.002515048908954043`). The active registry entry and the artifact agree.
- The console must describe a non-benign serving label as a **predicted label**, not as a confirmed attack and not as a calibrated probability.
- The serving bundle is registered as uncalibrated. D4 threshold transfer and D5 calibration describe this same RF configuration, but their held-out results still fail the detection gate; the available isotonic artifact has ECE ≈0.208.
- The registry records the threshold value, selection split, and artifact hash for each version, and the deployment gate refuses a serving artifact that differs from the approved active version.

## Claim audit

| Location | Claim or implication | Status | Correction |
| --- | --- | --- | --- |
| `README.md` highlights | "A trained scikit-learn Random Forest predicts benign and CIC-IDS-2017 attack labels." | **Corrected in README** | The registry-active serving bundle is the evaluated Random Forest seed 42. The README names the artifact and records its hash. |
| `README.md` highlights | "Operate a live console" and "optional local packet capture" | **Partially supported** | The console is real; live capture is disabled by default and feature parity is unvalidated. Keep the "optional/experimental" qualifier. |
| `README.md` architecture | "Network adapter → PyFlowMeter → live-flow API → inference and console" | **Prototype path** | This path exists but is not validated end to end. Do not imply it is the default or a production sensor. |
| Console page title / route | "Live flow tail", "live console" | **Interface vocabulary** | Acceptable only while the sensor state is visible and the data-boundary bar distinguishes `Live`, `Stored`, and `Demo`. |
| Console traffic mix | Implied label coverage from the serving artifact | **Corrected** | The note now says stored labels may come from other model versions or collectors. |
| Console confidence | "Confidence: Not available" | **Honest** | Do not add a confidence number unless it comes from a calibrated model with linked ECE/Brier evidence. |
| Threat-intel endpoint | AbuseIPDB enrichment | **Optional, not validated intelligence** | Enrichment is an external reputation lookup, not confirmed threat intelligence. Private and invalid IPs are not sent. |
| Research workbench | Per-family recall and PR-AUC | **Development evidence** | The CIC-IDS-2017 weekday results are failure-analysis evidence, not a blind final test. |
| Docs / plan | "9/10 detection efficacy" | **Not credible today** | Bot recall is 1.12%; five-seed FPR is 4.11% ± 3.27%; no external validation or human pilot. Keep the score below 9. |
| Docs / plan | "8/10 or 9/10 SaaS readiness" | **Not credible today** | Tenancy foundation, TOTP MFA and an OIDC client, SLO controls, encrypted backup tooling, a staging profile, Alembic, and a passing 20 flows/s load test exist, but there is no real IdP integration, penetration test, operated staging environment, operated off-host RPO/RTO, billing, or design-partner pilot. |
| Any UI copy | "Validated", "confirmed", "zero-day detection", "real-time threat intelligence" | **Not supported** | Remove or replace with "prediction", "candidate", "sample", or "optional enrichment". |

### Active versus legacy UI surfaces

The Flask app serves two templates. Any claim audit must distinguish them.

| Surface | Route | Template and script | Status | Claim rule |
| --- | --- | --- | --- | --- |
| Console | `/`, `/console` | `templates/console.html`, `static/js/console.js` | **Active** | Predictions are model output, not ground truth. No calibrated confidence. Sensor state and data boundary must stay visible. |
| Research workbench | `/research`, `/upload` | `templates/index.html`, `static/js/workbench.js` | **Active** | Frozen evaluation evidence and limitations. Development evidence is labelled as such. |
| Legacy dashboard | `/dashboard` | Redirects to `/` with HTTP 301 | **Removed** | The archived legacy dashboard was deleted from the repository. `static/js/main.js` remains legacy and is not referenced by any served route. |
| Legacy threat-intel/SOAR strings | none | `static/js/main.js` | **Not served** | Contains “confidence”, AbuseIPDB enrichment, and response-preview strings. They are not part of the active console and must not be cited as product behavior. |

If a legacy file is ever re-served, it must be re-audited before it can carry any claim. Until then, only the console and research workbench are product surfaces.

## Evidence status

- The sample random-row benchmark is exploratory.
- The CIC-IDS-2017 weekday split is development evidence and has already been inspected.
- The RF seed-42 result is: PR-AUC `0.7900`, ROC-AUC `0.7816`, test FPR `0.725%`, recall `57.94%`, precision `96.39%`, alert rate `15.06%`.
- Five-seed RF variation is: PR-AUC `0.7472 ± 0.0749`, ROC-AUC `0.7722 ± 0.0742`, recall `0.5830 ± 0.1479`, FPR `0.0411 ± 0.0327`, alert rate `17.68% ± 5.12%`.
- Per-family recall, seed 42: Bot `1.12%`, DDoS `63.56%`, Infiltration `55.56%`, PortScan `53.66%`, Web Brute Force `90.71%`, SQLi `42.86%`, XSS `93.56%`.
- The drift audit recorded 3 true warnings, 2 false warnings, 2 missed degradations, and 0 correctly quiet periods.
- The D9 cost-sensitive evaluation and release gate are complete; the gate **fails** 7 of 9 checks. The served RF breaks even at `C_FN/C_FP ≈ 1.21` at the 25.05% benchmark prevalence and `≈ 1.11` at a 100-alert budget; at 0.1% prevalence the five-seed break-even is about `72.47` under the all-alerts-reviewed model ([`PREVALENCE_EVAL.md`](PREVALENCE_EVAL.md)). Artifact identity and five-seed reporting pass.
- No independent external dataset and no real-capture label study exist. The only real capture is 11 operator-declared benign flows; it is not an FPR measurement.
- No prospective human-review pilot has been run. The S7 harness self-test is synthetic and is not pilot evidence.
- The S8 release gate is implemented and machine-checked; its current verdict is **FAIL** (6 pass, 1 fail, 2 blocked). The external security/readiness review is not commissioned.

## What this system does not claim

This section is the one-page boundary. It overrides optimistic wording anywhere else.

**NetShield does not claim:**

1. **Validated live detection.** The live-capture path is disabled by default. The upload path now covers all 80 features, but the live path drops ICMP/IPv6, the two extractors disagree numerically, and neither has CICFlowMeter ground truth. It has not been shown to produce features equivalent to the training pipeline.
2. **That artifact identity alone is detection evidence.** The console and the evaluation now load the same Random Forest seed 42 bytes, verified by SHA-256. That closes the provenance gap; it does not make the model accurate or externally validated.
3. **Calibrated confidence.** The serving Random Forest is registered as uncalibrated, so the console must not show a confidence percentage. The available isotonic calibration artifact has held-out ECE ≈0.208 and fails the 0.05 gate; its reliability diagrams, ECE, Brier score, and decision-curve results are not attached to serving output.
4. **Reliable unseen-attack detection.** Unseen-family recall varies from 1.12% (Bot) to 93.56% (XSS). Bot detection is effectively absent at the reported operating point.
5. **A stable operating threshold.** Test FPR ranges from 0.725% to 7.85% across seeds 42–46 in the weekday experiment, with per-day breaches documented in [THRESHOLD_POLICY_V2.md](THRESHOLD_POLICY_V2.md). The serving app applies the seed 42 threshold, but it does not transfer to every day.
6. **Threat intelligence.** AbuseIPDB enrichment, when enabled, is an external reputation lookup. It does not confirm an incident, attribute an actor, or validate a malicious host.
7. **Production readiness.** The repository has a tenancy/RBAC/audit foundation with TOTP MFA and an OIDC authorization-code client, S2 SLO definitions, metrics, logs, rate limits, backpressure, batch ingest, and an S3 model registry with hash/signature verification, a promotion path, tested rollback, and a deployment gate. It also has a `staging` profile, an Alembic baseline with a startup revision guard, and a preflight gate. It does not have a real IdP integration, a completed external penetration test, operated off-host backup with a measured RPO/RTO, an operated staging environment, production migration history, a staffed on-call rota, billing, a managed artifact and secret store, or a design-partner pilot. S4 has a built and scanned image with zero critical, zero Python, and zero fixable findings, a runtime dependency audit at zero advisories, and automated ZAP/Bandit checks in a checked-in CI workflow; 186 unfixed Debian OS advisories remain accepted baseline risk, the external penetration test is blocked, and enterprise readiness is not claimed.
8. **Multi-tenant SaaS readiness.** Tenant-scoped queries and isolation tests are a foundation, not proof of enterprise isolation. Shared database failure modes, backup/restore isolation, and cross-tenant operational access still require review.
9. **Automated response.** Response previews and webhook acknowledgments do not block hosts, change firewalls, contact Slack/PagerDuty/AWS/Cloudflare/TAXII, or execute containment.
10. **Coverage of every attack family or zero-day attacks.** The model predicts labels seen in its training vocabulary and, separately, may flag some unseen families. It does not identify arbitrary novel attacks.
11. **That a polished console is evidence of detection quality.** The console is a product surface. Its visual quality is not a model metric.
12. **That CIC-IDS-2017 performance transfers to another network.** No second dataset or real-capture validation has been completed.

**Allowed wording:** prediction, predicted label, non-benign prediction, candidate alert, sample data, replay sample, stored record, optional IP reputation enrichment, development evidence, prototype.

**Disallowed wording unless separately proven:** confirmed attack, malicious host, validated detection, live sensor validated, calibrated confidence, zero-day detection, threat intelligence, production-ready, enterprise-ready, 9/10 detection, 9/10 SaaS.

## Change control

Any change to the serving artifact, feature schema, threshold policy, label space, or tenant boundary must update this document and the model card in the same change. A release that cannot state its artifact hash, feature schema, threshold policy, and evaluation evidence does not get a detection claim.
