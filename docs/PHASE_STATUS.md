# Phase Status Audit (D0–D9, S0–S8, P0–P9)

**Status:** audit of the repository at 2026-11-11.
**Rule:** a phase is **done** only when its exit gate is met and the evidence is committed. A phase that produced a protocol, harness, or negative result without meeting its exit gate is **partial**. A phase that requires an external actor or evidence the assistant cannot obtain is **blocked**.

This page is the single map from the requested track/phase list to the artifacts that actually exist. It does not replace those artifacts and it does not raise any score.

**Frozen scope (P0, 2026-11-13):** flow-based detector for volumetric and scanning behavior. Not a general NIDS. Live accuracy is unvalidated. Botnet, web attacks, infiltration, zero-day, and blocking are out of scope. Claim-to-artifact mapping: [`CLAIM_EVIDENCE_MATRIX.md`](CLAIM_EVIDENCE_MATRIX.md).

## Prompt-pack execution (P0–P9)

This sequence is separate from Track P below. It is the re-scope execution pack, not the product-console track.

| Phase | Status | Evidence |
| --- | --- | --- |
| P0 scope freeze | **Done** | [`CLAIM_EVIDENCE_MATRIX.md`](CLAIM_EVIDENCE_MATRIX.md), scope ribbon, `/dashboard` 301, `tests/test_scope_routes.py` |
| P1 prevalence | **Done** | [`PREVALENCE_EVAL.md`](PREVALENCE_EVAL.md), [`PREVALENCE_EVAL.json`](PREVALENCE_EVAL.json), `scripts/prevalence_eval.py`, `tests/test_prevalence_eval.py` |
| P2A labels/schema/rules | **Done (Tier A only)** | [`LABEL_POLICY.md`](LABEL_POLICY.md), [`PORTABLE_FEATURES.md`](PORTABLE_FEATURES.md), [`RULE_BASELINES.md`](RULE_BASELINES.md), [`rule_baselines.json`](rule_baselines.json), `scripts/rule_baselines.py`, `tests/test_rule_baselines.py`. Tier B fan-out is unavailable because no raw packets exist; it is not approximated. |
| P2B model | **Blocked** | [`P2B_PROTOCOL_ANALYSIS.md`](P2B_PROTOCOL_ANALYSIS.md), [`P2B_RISK_REGISTER.md`](P2B_RISK_REGISTER.md), [`P2B_RESIDUAL_RISK_ACCEPTANCE.md`](P2B_RESIDUAL_RISK_ACCEPTANCE.md), [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md), [`VOLUMETRIC_DETECTOR.md`](VOLUMETRIC_DETECTOR.md), [`p2b_protocol_analysis.json`](p2b_protocol_analysis.json), [`VOLUMETRIC_MODEL.json`](VOLUMETRIC_MODEL.json), `scripts/p2b_protocol_analysis.py`, `scripts/volumetric_model.py`, `tests/test_p2b_protocol_analysis.py`, `tests/test_volumetric_model.py`. Monday-Tuesday has 0 volumetric/scan positives; Wednesday validation families (DoS) and Friday test families (DDoS/PortScan) are disjoint, and Wednesday's families are time-separated. No model or registry row was created; the serving artifact is unchanged. |
| P2B scoped external | **Partial (scoped DoS/DDoS)** | [`P2B_SCOPED_EXTERNAL.md`](P2B_SCOPED_EXTERNAL.md), [`p2b_scoped_external.json`](p2b_scoped_external.json), `scripts/p2b_scoped_external.py`, `tests/test_p2b_scoped_external.py`. Leakage-safe group split of CIC-IDS-2018 (11,717,527 unique rows): 70% train, 15% validation, 15% test, 5 seeds, 800k train cap, validation-only thresholds. Coverage gate passes for DoS and DDoS. At 100 alerts/10k, logistic regression reaches 10.12% recall at 0.16% FPR; RF seed 42 reaches 0.02% because its uncalibrated validation scores saturate at 0.9999996753, so both budgets select the same threshold; isolation forest is near-random (ROC-AUC 0.49). PortScan is absent and not claimed. The serving artifact and threshold are unchanged. |
| P3 cross-dataset | **Partial (negative transfer)** | [`CROSS_DATASET.md`](CROSS_DATASET.md), [`cross_dataset_results.json`](cross_dataset_results.json), [`CROSS_DATASET_MAPPING.md`](CROSS_DATASET_MAPPING.md), `scripts/cross_dataset_transfer.py`, `tests/test_cross_dataset_transfer.py`. A frozen Tier A (12-feature) model was trained on CIC-IDS-2017 with a stratified group split and transferred unchanged to CIC-IDS-2018 and UNSW-NB15. CIC-IDS-2018: 11,717,527 rows after dedup, 8.60% prevalence, ROC-AUC 0.7241, AP 0.2048; at a label-free 100-alert/10k rank budget, recall 2.34%, FPR 0.87%, PPV 20.09%. UNSW-NB15: 38,375 rows, 10.86% prevalence, ROC-AUC 0.3793, AP 0.1028; at 100 alerts/10k, recall 0.73%, FPR 1.03%, PPV 7.88%. The frozen strict threshold (1.0) emits 0 alerts on both datasets; CIC-IDS-2018 has 333,755 tied rows at 1.0 (20.09% positive) and UNSW-NB15's maximum score is 0.1855. The serving artifact and threshold are unchanged, and P2B remains blocked. Data audits: [`EXTERNAL_DATASET_AUDIT.md`](EXTERNAL_DATASET_AUDIT.md), [`CIDDS002_AUDIT.md`](CIDDS002_AUDIT.md); CIDDS-002 stays blocked (unidirectional NetFlow, 9/12 features, licence unverified). |
| P3B portable-ratio transfer | **Partial (ranking improved, absolute result weak)** | [`PORTABLE_TRANSFER.md`](PORTABLE_TRANSFER.md), [`portable_transfer_results.json`](portable_transfer_results.json), `scripts/portable_transfer.py`, `tests/test_portable_features.py`. A separate 8-feature ratio-only candidate was trained on the original CIC-IDS-2017 export with the same stratified group split, external deduplication, and validation-only threshold policy as P3. CIC-IDS-2018: 11,717,527 rows, 8.5978% prevalence, ROC-AUC 0.7785 vs 0.7241, AP 0.2271 vs 0.2048. UNSW-NB15: 38,375 rows, 10.8638% prevalence, ROC-AUC 0.4956 vs 0.3793, AP 0.1088 vs 0.1028, only 0.0001 above chance-level AP. Both validation budgets selected a threshold of 1.000000, so strict external alerts are zero by construction, not a measured false-positive rate. The serving artifact, frozen Tier A schema, and P3 registry row are unchanged. |
| P3C corrected-label sensitivity | **Done (sensitivity; confounded)** | [`CORRECTED_LABEL_SENSITIVITY.md`](CORRECTED_LABEL_SENSITIVITY.md), [`corrected_label_sensitivity.json`](corrected_label_sensitivity.json), `scripts/corrected_label_sensitivity.py`, `tests/test_corrected_label_sensitivity.py`. Strict frozen policy on the DistriNet release: case/spelling aliases only, every `- Attempted` and `Infiltration - Portscan` row excluded. 2,008,410 of 2,099,976 rows kept at 21.2030% prevalence. Grouped-test ROC-AUC 0.9988, AP 0.9916 versus 0.9859 / 0.9297 on the original-Kaggle P3B arm; test prevalence differs (21.2914% vs 19.0942%). Both thresholds saturate at 1.000000, so strict test alerts are zero by construction. The release is also a CICFlowMeter re-extraction, so the gain cannot be attributed to labels alone, and it is not external evidence. |
| P4 live parity | Blocked | Needs CICFlowMeter and a real capture |
| P5 scale | Not started | Depends on P2B |
| P6 integrations | Not started | Depends on P2B and P5 |
| P7 operated controls | Blocked | Needs infrastructure and a commissioned pen test |
| P8 pilot | Blocked | Needs a partner and ethics approval |
| P9 paper | Not started | Depends on P1–P5 and P8 optional |

## Scorecard (unchanged)

| Dimension | Score | Why it is not higher |
| --- | ---: | --- |
| Detection efficacy | **4/10** | No held-out evidence raises Bot/unseen-family recall at ≤1% FPR; no external dataset; no human pilot. Serving and evaluation now use the same RF artifact, but that is an evidence fix, not a detection gain. |
| Production SaaS readiness | **3/10** | No external review, managed secrets, operated staging, real IdP integration, production migration history, operated off-host backup with measured RPO/RTO, billing, or pilot. TOTP MFA, an OIDC client, a staging profile, Alembic, and a preflight gate now exist, but they are not operated evidence. |
| Research demo | **6/10** | The console and workbench are runnable and the failure analysis is honest, but the detector is weak and live capture is unvalidated. |
| Evidence quality | **9/10** | Frozen protocol, per-family gates, negative results, hashes, reproducibility, and explicit blockers. |
| UI / operator console | **8/10** | Product-grade console with review workflow, filters, provenance, sensor identity, and honest data-boundary copy. Not evidence of detection quality. |

**Detection ≥7 and SaaS ≥7 are not supported by the current evidence.** The phase work below improves honesty, reproducibility, security posture, and operator usability. It does not create detection or SaaS evidence that does not exist.

## Track D — Detection efficacy

| Phase | Status | Evidence | Exit gate | Remaining blocker |
| --- | --- | --- | --- | --- |
| D0 scope and claims | **Done** | [`SCOPE_AND_CLAIMS.md`](SCOPE_AND_CLAIMS.md), [`PROJECT_SCOPE.md`](PROJECT_SCOPE.md) | One scope statement, provenance statement, operating-point definition, no unsupported claims | None. Serving, evaluation, and gating now use the same artifact hash; remaining claims are bounded. |
| D1 evaluation protocol | **Done** | [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md) | Frozen splits, class-coverage rules, threshold rules, primary metrics, per-family targets | None for the protocol. Final test results are not used for selection. |
| D2 data/label/feature audit | **Done** | [`DATA_PIPELINE_AUDIT.md`](DATA_PIPELINE_AUDIT.md), [`data_pipeline_audit.json`](data_pipeline_audit.json) | Source hashes, class distributions, duplicates, missing/infinite counts, feature-name consistency, confirmed defects | None. Known defects are documented and fixed where confirmed. |
| D3 baselines | **Done** | [`BASELINE_RESULTS_V2.md`](BASELINE_RESULTS_V2.md), [`baseline_results_v2.json`](baseline_results_v2.json) | Per-family recall, PR-AUC, frozen-threshold FPR, alert volume, calibration, runtime, seed variation | No baseline passes all predeclared gates. This is a result, not a blocker. |
| D4 threshold transfer | **Done** | [`THRESHOLD_POLICY_V2.md`](THRESHOLD_POLICY_V2.md), [`threshold_policy_v2.json`](threshold_policy_v2.json) | Validation-selected threshold applied unchanged to held-out days and seeds, with reported cost | The global threshold does not transfer; FPR ranges 0.73%–7.85% across seeds. Reported as failure. |
| D5 calibration | **Done** | [`CALIBRATION_V2.md`](CALIBRATION_V2.md), [`calibration_v2.json`](calibration_v2.json) | Reliability diagrams, ECE, Brier, decision curve, documented calibration method | Held-out ECE remains high (about 0.25); the served RF is registered as uncalibrated because the available isotonic artifact has ECE ≈0.208. No confidence number is shown in the UI. |
| D6 unseen-family/Botnet | **Done (negative result)** | [`UNSEEN_FAMILY_AND_BOTNET.md`](UNSEEN_FAMILY_AND_BOTNET.md), [`d6_unseen_family_results.json`](d6_unseen_family_results.json) | Document whether Bot recall can rise without unacceptable FPR; state honestly if it cannot | No arm reaches Bot recall ≥0.50 at ≤1% FPR. Best arm is 20.7% ± 16.6% at 8.65% ± 1.37% FPR. Detection stays 4/10. |
| D7 external validation | **Partial / blocked** | [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md), [`external_validation_harness_selftest.json`](external_validation_harness_selftest.json), [`d7_real_capture_benign.json`](d7_real_capture_benign.json), [`CROSS_DATASET.md`](CROSS_DATASET.md) | Second dataset and real-capture evaluation with feature mapping, label source, limitations | P3/P3B now score CIC-IDS-2018 and UNSW-NB15, but both are negative or mixed transfer and neither is a clean independent replication of the live path. The only real capture is 11 operator-declared benign flows. No labelled live traffic exists. |
| D8 prospective pilot | **Partial / blocked** | [`D8_PROSPECTIVE_PILOT_PROTOCOL.md`](D8_PROSPECTIVE_PILOT_PROTOCOL.md), [`D8_PILOT_OUTCOME_TEMPLATE.md`](D8_PILOT_OUTCOME_TEMPLATE.md) | Pilot protocol, human-reviewed alerts, measured analyst time, measured FP cost, outcome report | No design partner, consent, or human review. Simulated feedback is not a human study. |
| D9 cost-sensitive gate | **Done (gate fails)** | [`COST_MODEL_AND_RELEASE_GATE.md`](COST_MODEL_AND_RELEASE_GATE.md), [`COST_SENSITIVE_RESULTS.json`](COST_SENSITIVE_RESULTS.json) | Cost matrix, expected cost, release gate, reproducible evidence package | Gate fails 7 of 9 checks. Artifact identity and five-seed reporting pass. Served RF break-even `r≈1.21` at the 25.05% benchmark prevalence and `≈1.11` at 100 alerts/10k; at 0.1% prevalence the five-seed break-even is about 72.47 ([`PREVALENCE_EVAL.md`](PREVALENCE_EVAL.md)). Alert rate and unseen-family recall still fail. |

**Track D conclusion:** all requested analysis phases exist. D7 and D8 cannot be completed without external data and people. Detection remains **4/10**.

## Track S — SaaS readiness

| Phase | Status | Evidence | Exit gate | Remaining blocker |
| --- | --- | --- | --- | --- |
| S0 product boundary/threat model | **Done** | [`PRODUCT_BOUNDARY_AND_THREAT_MODEL.md`](PRODUCT_BOUNDARY_AND_THREAT_MODEL.md), [`PRIVACY_AND_DATA_LIFECYCLE.md`](PRIVACY_AND_DATA_LIFECYCLE.md) | Boundary document, data classification, threat model | None. The product is stated as hybrid, offline-first, with an experimental live path. |
| S1 tenancy/identity/audit | **Done (foundation)** | [`TENANCY_AND_ACCESS_CONTROL.md`](TENANCY_AND_ACCESS_CONTROL.md), [`STAGING_AND_MIGRATIONS.md`](STAGING_AND_MIGRATIONS.md), `tests/test_tenancy.py`, `tests/test_mfa.py`, `tests/test_oidc.py` | Query-layer tenant scoping, SSO, roles, audit log, retention/deletion | TOTP MFA and an OIDC authorization-code client are implemented and tested against a fake provider. No real IdP integration, SAML, SCIM, session revocation, or external isolation review. Foundation only. |
| S2 reliability/observability | **Done (controls) / SLO met at 20 flows/s** | [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md), [`LOAD_TEST_RESULTS.md`](LOAD_TEST_RESULTS.md), [`load_test_results.json`](load_test_results.json) | SLOs, dashboards, alerts, load test, rate limits, backpressure | Latest run: p95 164.9 ms at 20 flows/s with 100% success. Batch inference, removal of per-row refresh queries, and SQLite WAL tuning closed the gap. Capacity above 20 flows/s was not re-measured. |
| S3 registry/versioning/rollback | **Done** | [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md), `training/model_registry.py`, `scripts/deployment_check.py` | Every prediction records model version, hash, schema, threshold, calibration; rollback tested | The registry-active serving artifact is now the evaluated RF seed 42; the deployment hash and feature-schema checks pass. |
| S4 security/privacy/compliance | **Partial / blocked** | [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md), [`SECURITY_FINDINGS.json`](SECURITY_FINDINGS.json), [`sbom.cdx.json`](sbom.cdx.json), [`security_gate.json`](security_gate.json) | Dependency scan, secret management, SBOM, privacy review, external penetration test with remediation | Scans and SBOM exist. No managed secret store and no external penetration test. 186 unfixed base-image advisories remain accepted risk. |
| S5 deployment/runbooks/backup/IR | **Done (local + encrypted drill) / partial** | [`STAGING_AND_MIGRATIONS.md`](STAGING_AND_MIGRATIONS.md), [`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md), [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md), [`backup_restore_drill.json`](backup_restore_drill.json), [`encrypted_backup_drill.json`](encrypted_backup_drill.json), `scripts/backup_encrypted.py`, `scripts/preflight.py`, `migrations/`, `tests/test_staging_config.py` | Reproducible deployment, migrations, backup/restore drill, DR procedure, incident runbooks | Local and AES-256-GCM drills pass, including authenticated restore and off-host-directory hash verification. Alembic baseline, startup revision guard, staging profile, and preflight gate exist and are tested. No IaC, operated staging environment, production migration history, operated off-host storage, or site-measured RPO/RTO. |
| S6 onboarding/billing/support | **Done (non-commercial)** | [`ONBOARDING_AND_SUPPORT.md`](ONBOARDING_AND_SUPPORT.md) | Onboarding path, support model, billing or explicit non-commercial statement | No customers, price, SLA, billing, or usage metering. The document states this explicitly. |
| S7 design-partner pilot | **Blocked / not run** | [`S7_PILOT_PREREGISTRATION.md`](S7_PILOT_PREREGISTRATION.md), [`S7_PILOT_OUTCOME.md`](S7_PILOT_OUTCOME.md), `scripts/pilot_analysis.py`, `tests/test_pilot_analysis.py` | Real pilot with measured onboarding, yield, analyst time, support load | No design partner, consent, data-handling approval, or real dispositions. The self-test is synthetic and is never cited as pilot data. |
| S8 external review/release gate | **Gate implemented / external review blocked** | [`S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md`](S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md), [`s8_external_review.json`](s8_external_review.json), [`s8_release_gate.json`](s8_release_gate.json), `scripts/release_gate.py` | External review completed, critical findings closed, gate signed off, evidence published | No external reviewer engaged. The machine gate is **FAIL** (6 pass, 1 fail, 2 blocked). |

**Track S conclusion:** the technical foundation is real, but SaaS readiness is **3/10**. The missing items are external and operational, not documentation.

## Track P — Product console

| Phase | Status | Evidence | Exit gate | Remaining blocker |
| --- | --- | --- | --- | --- |
| P0 product surface | **Done** | `templates/console.html`, `static/js/console.js`, `static/css/console.css` | Sensor health, interface, BPF filter, ingest, store, flagged rate, flow rate, chart, mix, tail, follow, filters, search, inspector, review, export, data-boundary bar | None. The surface is an operational prototype, not detection evidence. |
| P1 real live path | **Blocked** | [`FEATURE_PARITY_LIVE_CAPTURE_V2.md`](FEATURE_PARITY_LIVE_CAPTURE_V2.md), [`LIVE_CAPTURE_OPERATIONS.md`](LIVE_CAPTURE_OPERATIONS.md), [`live_capture_smoke.json`](live_capture_smoke.json) | End-to-end live validation with reference features, matching rules, unmatched rate, error distributions, parser behavior, schema versions | No CICFlowMeter ground truth; live path drops ICMP/IPv6; extractors disagree numerically. Capture is ingest-only and must show Stored/Disabled, not “live validated”. |
| P2 operator workflow | **Done** | `static/js/console.js`, `tests/` UI-adjacent API tests | Filters, search, pause/resume, follow, selection, review status, notes, CSV export, keyboard shortcuts | None. The workflow is usable; its quality is not a detection metric. |
| P3 product hardening | **Done (foundation)** | `app.py` sensor columns and `/api/sensors/summary`, `tests/test_sensor_identity.py`, console sensor filter, inspector, alert-budget status | Sensor identity, per-sensor health, tenant-scoped queues, role-aware review, retention controls, visible data boundary, alert-budget reporting | Multi-tenant operation still lacks external review and managed secrets. Sensor identity is collector-supplied and nullable; legacy rows stay unattributed. |

**Track P conclusion:** P0 and P2 are done, P3 now has a tested sensor-identity foundation, and P1 remains blocked on feature parity and labelled live traffic. UI is **8/10** as a product surface, not as evidence of detection.

## What is genuinely missing

| Missing item | Track | Why it matters | Who can unblock it |
| --- | --- | --- | --- |
| Second dataset with a clean, schema-compatible replication | D7 | External validity cannot rest on CIC-IDS-2017 alone, and CIC-IDS-2018/UNSW-NB15 transfer is negative or mixed | Anyone who can supply a licensed, schema-compatible dataset or labelled capture |
| Labelled real capture | D7 | Real-network feature parity and FPR are unmeasured | A site with consent and human labels |
| Human pilot | D8/S7 | Analyst time, yield, and support load are assumptions | A consenting design partner |
| External penetration test | S4/S8 | Enterprise readiness cannot be self-certified | An independent security firm |
| External readiness review | S8 | The final gate must be adversarial | An independent reviewer |
| Managed secrets, real IdP integration, operated staging, production migration history | S1/S4/S5 | Production operation needs them | Engineering and infrastructure work |
| Operated off-host backup with measured RPO/RTO | S5 | The encrypted drill proves the procedure, not durable off-host storage or a site SLO | Infrastructure work |
| Billing and usage metering | S6 | Only relevant if the product becomes commercial | Product/business decision |

## Recommended next steps (priority order)

| Priority | Action | Why it moves the project | Expected score effect |
| ---: | --- | --- | --- |
| 1 | **Raise Bot/unseen-family recall at ≤1% FPR.** Continue D6 with a genuinely open-set method and predeclared gates. | Bot recall is the core research failure; artifact identity is now fixed. | Detection can move above 4 only with a positive, reproduced result. |
| 2 | **Reduce false positives and alert volume.** Use the alert-budget policy and report per-day transfer. | The served RF produces a 17.7% alert rate at its frozen threshold and only 3.6% recall at 100 alerts/10k. | Required before a scoped usefulness claim. |
| 3 | **Calibrate the served artifact.** Fit temperature or isotonic calibration on validation and report ECE/Brier on test. | The existing isotonic artifact has ECE ≈0.208, so the UI correctly shows no confidence. | Improves trust and analyst workflow, not ranking. |
| 4 | **Obtain a second dataset.** Use a licensed, schema-compatible public dataset and document mapping. | One academic dataset cannot establish external validity. | Required for detection ≥7. |
| 5 | **Run a real pilot.** Recruit a consenting design partner and measure onboarding, yield, review time, and support load. | Replaces assumptions with human evidence. | Required for SaaS ≥7. |
| 6 | **Commission the external penetration test and readiness review.** | Self-certification is not assurance. | Required for SaaS ≥7 and S8 pass. |
| 7 | **Add managed secrets and operate the implemented MFA/OIDC/staging/migrations.** | These are table stakes for a hosted service; the code exists but is not an operated control. | Required for SaaS ≥7. |
| 8 | **Operate the encrypted backup off-host and measure RPO/RTO.** | The drill proves the procedure, not durable off-host storage or a site SLO. | Required for SaaS ≥7. |
| 9 | **Re-measure ingest above 20 flows/s.** | The 20 flows/s SLO now passes; saturation behavior after batch inference and WAL tuning is unknown. | Required for a capacity claim. |
| 10 | **Add billing and usage metering.** | Only relevant if the product becomes commercial. | Required for a commercial SaaS claim. |

Do not reorder these to chase a score. The score is a consequence of the evidence, not a target to negotiate.

## IDS/IPS roadmap

The staged IDS-then-IPS plan is in [`IDS_IPS_ROADMAP.md`](IDS_IPS_ROADMAP.md). It is a planning document, not implemented capability. It adds no detection or SaaS evidence, and no phase in it raises the current scores by itself.

## Honest bottom line

- The requested phases are **implemented as far as the repository and the assistant can take them**.
- D7, D8/S7, S4’s external test, and S8’s external review are **blocked on external evidence or people**. They are reported as blocked, not faked.
- Detection stays **4/10** and production SaaS stays **3/10**.
- Research evidence is **9/10** and the UI is **8/10**. Those two exceed 7; detection and SaaS do not.
- The next honest step is not another document. It is: reduce FPR/alert volume, raise Bot recall with held-out evidence, obtain a second dataset, commission the external test, and run a real pilot. Serving/evaluation artifact identity is now closed.
