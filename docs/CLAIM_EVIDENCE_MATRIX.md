# Claim–Evidence Matrix (Phase P0)

**Status:** active. This file is the single source of truth for public claims in the bounded P0 scope.
**Date:** 2026-11-13.
**Owner:** NetShield maintainers.
**Rule:** a claim without an artifact, hash, or reproducible command is not a claim. It is removed, qualified, or marked UNSUPPORTED.

## Status values

| Status | Meaning |
| --- | --- |
| **SUPPORTED** | An artifact or reproducible command in this repository directly supports the claim as written. |
| **CONDITIONAL** | The claim is true only with the stated qualifier (development evidence, single run, foundation only, fake-provider test). |
| **UNSUPPORTED** | No artifact supports the claim; the claim must be removed or rewritten. |
| **BLOCKED** | The claim needs an external input the project does not have (dataset, IdP, pen test, partner, pilot). |

## Bounded scope

These are the only files this matrix governs in P0:

- `templates/index.html`, `templates/console.html`, `templates/account.html`, `templates/login.html`
- `README.md`, `docs/SCOPE_AND_CLAIMS.md`, `docs/MODEL_CARD.md`, `docs/PHASE_STATUS.md`
- `app.py` route docstrings and API error text

Claims outside this scope are not audited here and must not be cited as product behavior.

## Frozen scope statement

> Flow-based detector for volumetric and scanning behavior. Not a general NIDS. Live accuracy is unvalidated. Botnet, web attacks, infiltration, zero-day, and blocking are out of scope.

## Serving identity

| Item | Value | Source |
| --- | --- | --- |
| Serving artifact | `models/model_bundle_rf_day_based_seed42.pkl` | `models/registry/registry.json` |
| SHA-256 | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` | `sha256sum models/model_bundle_rf_day_based_seed42.pkl` |
| Version | `serving-rf-day-based-seed42-v1` | `models/registry/registry.json` |
| Threshold | `1 - P(BENIGN) >= 0.002515048908954043` | `models/registry/registry.json` |
| Calibration | `uncalibrated` | `models/registry/registry.json` |
| Feature count | 80 | artifact `feature_names` / `models/metrics_rf_day_based_seed42.json` |

## Matrix

| claim_id | claim | location | artifact | hash or command | status | owner |
| --- | --- | --- | --- | --- | --- | --- |
| C-001 | The serving artifact is the evaluated Random Forest seed 42 bundle, identified by SHA-256. | README highlights; `SCOPE_AND_CLAIMS.md`; console mix note | `models/model_bundle_rf_day_based_seed42.pkl`; `models/registry/registry.json` | `sha256sum models/model_bundle_rf_day_based_seed42.pkl` | SUPPORTED | maintainers |
| C-002 | The serving decision rule is `1 - P(BENIGN) >= 0.002515048908954043`. | `SCOPE_AND_CLAIMS.md`; model card | `models/registry/registry.json` | `grep 0.002515048908954043 models/registry/registry.json` | SUPPORTED | maintainers |
| C-003 | The serving artifact declares 80 statistical flow features. | `SCOPE_AND_CLAIMS.md`; model card; README | `models/metrics_rf_day_based_seed42.json`; artifact `feature_names` | `venv/Scripts/python.exe -c "import json;print(len(json.load(open('models/metrics_rf_day_based_seed42.json'))['features']))"` | SUPPORTED | maintainers |
| C-004 | Evaluation uses a Monday–Tuesday train, Wednesday validation, Thursday–Friday test day split. | Research workbench; `SCOPE_AND_CLAIMS.md`; model card | `docs/TEMPORAL_HOLDOUT_RESULTS.md`; `docs/summary_metrics.json` | artifact review | SUPPORTED | maintainers |
| C-005 | Seed-42 test metrics are PR-AUC 0.7900, ROC-AUC 0.7816, FPR 0.725%, recall 57.94%, precision 96.39%, alert rate 15.06%. | Research workbench; `SCOPE_AND_CLAIMS.md` | `models/metrics_rf_day_based_seed42.json` | artifact review | CONDITIONAL — development evidence, already inspected; not a blind confirmatory test | maintainers |
| C-006 | Five-seed variation is PR-AUC 0.7472 ± 0.0749, FPR 0.0411 ± 0.0327, recall 0.5830 ± 0.1479. | Research workbench; `SCOPE_AND_CLAIMS.md` | `docs/summary_metrics.json`; `docs/baseline_results_v2.json` | artifact review | CONDITIONAL — mean and SD across seeds 42–46, same development split | maintainers |
| C-007 | Per-family recall (seed 42) ranges from Bot 1.12% to XSS 93.56%. | Research workbench; `SCOPE_AND_CLAIMS.md` | `docs/d6_unseen_family_results.json`; `docs/summary_metrics.json` | artifact review | CONDITIONAL — flagging rate, not family identification | maintainers |
| C-008 | Live accuracy is unvalidated. | Console data bar; scope statement; model card | `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md`; `docs/LIVE_CAPTURE_OPERATIONS.md` | artifact review | SUPPORTED (negative claim) | maintainers |
| C-009 | Live capture is optional and experimental; the console is the primary runnable surface. | README maturity note; console copy | `README.md`; `docs/LIVE_CAPTURE_OPERATIONS.md` | repository review | SUPPORTED | maintainers |
| C-010 | The live BPF path drops ICMP and IPv6 while the upload path keeps them. | README; `SCOPE_AND_CLAIMS.md`; model card | `docs/FEATURE_PARITY_LIVE_CAPTURE_V2.md` | artifact review | SUPPORTED | maintainers |
| C-011 | Console labels are model predictions, not ground truth. | Console data bar; console titles | `templates/console.html`; `static/js/console.js` | `grep -n "not ground truth" templates/console.html` | SUPPORTED | maintainers |
| C-012 | No confidence percentage is shown because the serving artifact is uncalibrated. | Console mix note; `SCOPE_AND_CLAIMS.md`; model card | `models/registry/registry.json`; `docs/CALIBRATION_V2.md` | registry review | SUPPORTED | maintainers |
| C-013 | AbuseIPDB enrichment is optional and is not confirmed threat intelligence. | README highlights; `SCOPE_AND_CLAIMS.md` | `app.py` enrichment path; `docs/SCOPE_AND_CLAIMS.md` | `grep -n "AbuseIPDB" app.py` | CONDITIONAL — external reputation lookup only | maintainers |
| C-014 | Tenant isolation, RBAC, audit, and retention are a tested foundation. | README; `SCOPE_AND_CLAIMS.md` | `tests/test_tenancy.py`; `docs/TENANCY_AND_ACCESS_CONTROL.md` | `venv/Scripts/python.exe -m pytest tests/test_tenancy.py -q` | CONDITIONAL — foundation, not an external isolation audit | maintainers |
| C-015 | OIDC authorization-code flow with PKCE, state/nonce, and RS256 verification is implemented and tested. | README; `SCOPE_AND_CLAIMS.md` | `tests/test_oidc.py`; `docs/TENANCY_AND_ACCESS_CONTROL.md` | `venv/Scripts/python.exe -m pytest tests/test_oidc.py -q` | CONDITIONAL — tested against a fake provider; no real IdP | maintainers |
| C-016 | A 20 flows/s ingest run measured p95 164.9 ms with 100% success. | `SCOPE_AND_CLAIMS.md`; model card; phase status | `docs/LOAD_TEST_RESULTS.md`; `docs/load_test_results.json` | artifact review | CONDITIONAL — one run; capacity above 20 flows/s unmeasured | maintainers |
| C-017 | The project is production-ready. | Any UI or README copy | none | — | UNSUPPORTED | maintainers |
| C-018 | The detector is a general NIDS covering all attack families. | Any UI or README copy | none | — | UNSUPPORTED | maintainers |
| C-019 | The detector detects zero-day attacks. | Any UI or README copy | none | — | UNSUPPORTED | maintainers |
| C-020 | The detector reliably detects botnet or unseen-family attacks. | Any UI or README copy | `docs/d6_unseen_family_results.json` | artifact shows Bot recall ~1% | UNSUPPORTED | maintainers |
| C-021 | CIC-IDS-2017 performance transfers to an independent dataset. | Any UI or README copy | `docs/CROSS_DATASET.md`; `docs/cross_dataset_results.json` | P3 evaluated CIC-IDS-2018 and UNSW-NB15; transfer is negative | UNSUPPORTED — refuted by P3 (2026-11-13); frozen threshold emits 0 alerts on both external datasets | maintainers |
| C-022 | A human pilot measured analyst yield, time, or false-positive cost. | Any UI or README copy | `docs/S7_PILOT_OUTCOME.md` | states pilot not run | BLOCKED — no partner or consent | maintainers |
| C-023 | An external penetration test has been completed. | Any UI or README copy | `docs/SECURITY_FINDINGS.json` | no external report | BLOCKED — not commissioned | maintainers |
| C-024 | Off-host backup has a measured operational RPO/RTO. | Any UI or README copy | `docs/backup_restore_drill.json`; `docs/encrypted_backup_drill.json` | local drill only | BLOCKED — operated off-host storage absent | maintainers |
| C-025 | The console blocks hosts, changes firewalls, or executes containment. | Any UI or README copy | `docs/SCOPE_AND_CLAIMS.md` | response previews only | UNSUPPORTED — out of scope | maintainers |
| C-026 | Detection efficacy is 9/10. | Any doc or UI | `docs/PHASE_STATUS.md` | score is 4/10 | UNSUPPORTED | maintainers |
| C-027 | Production SaaS readiness is 9/10. | Any doc or UI | `docs/PHASE_STATUS.md` | score is 3/10 | UNSUPPORTED | maintainers |
| C-028 | `/dashboard` is a legacy route that redirects to the console. | README API table; `SCOPE_AND_CLAIMS.md` | `app.py` `/dashboard` route | `venv/Scripts/python.exe -m pytest tests/test_scope_routes.py -q` | SUPPORTED after P0 (301) | maintainers |
| C-029 | A matching artifact hash is detection evidence. | Any UI or README copy | `SCOPE_AND_CLAIMS.md` | explicit disclaimer | UNSUPPORTED — provenance only | maintainers |
| C-030 | The model identifies arbitrary novel attacks. | Any UI or README copy | none | — | UNSUPPORTED | maintainers |
| C-031 | The prevalence harness uses per-flow held-out scores and a stratified bootstrap, not a parametric fallback. | `docs/PREVALENCE_EVAL.md`; `scripts/prevalence_eval.py` | `models/eval_cache/rf_seed{42..46}_test.npz`; `docs/PREVALENCE_EVAL.json` | `venv/Scripts/python.exe scripts/prevalence_eval.py ...` records `method: bootstrap_scores` | SUPPORTED | maintainers |
| C-032 | Seed 42 at 0.1% prevalence has PPV 7.40% and 78.27 alerts per 10,000 flows. | `docs/PREVALENCE_EVAL.md`; workbench Prevalence view | `docs/PREVALENCE_EVAL.json` | artifact review; recompute from TPR/FPR | SUPPORTED | maintainers |
| C-033 | Five-seed mean-rate PPV at 0.1% prevalence is 1.40%; per-seed mean PPV is 3.13% ± 3.06%. | `docs/PREVALENCE_EVAL.md`; workbench Prevalence view | `docs/PREVALENCE_EVAL.json` | artifact review | SUPPORTED | maintainers |
| C-034 | The D9 break-even 1.21 is a five-seed mean at 25.05% benchmark prevalence under the all-alerts-reviewed model, not a prevalence-free constant. | `docs/PREVALENCE_EVAL.md`; workbench Prevalence view | `docs/PREVALENCE_EVAL.json`; `docs/COST_SENSITIVE_RESULTS.json` | artifact review; `d9_break_even_1_21` block | SUPPORTED | maintainers |
| C-035 | At 0.1% prevalence the five-seed all-alerts break-even is about 72.47, roughly two orders of magnitude above 1.21. | `docs/PREVALENCE_EVAL.md` | `docs/PREVALENCE_EVAL.json` | artifact review | SUPPORTED | maintainers |
| C-036 | The P2A label mapping uses the exact CIC-IDS-2017 strings; unknown labels fail closed and missing labels are removed, never treated as benign. | `docs/LABEL_POLICY.md`; `scripts/rule_baselines.py` | `docs/rule_baselines.json` (`label_audit`); `tests/test_rule_baselines.py` | `venv/Scripts/python.exe -m pytest tests/test_rule_baselines.py -q` | SUPPORTED | maintainers |
| C-037 | The portable Tier A schema is frozen; Tier B fan-out is unavailable because the repository has no raw packets and no stateful aggregator. | `docs/PORTABLE_FEATURES.md`; `docs/RULE_BASELINES.md` | `docs/rule_baselines.json` (`fanout`, `data_inventory`) | artifact review; recursive `.pcap`/`.pcapng` search returns 0 | SUPPORTED | maintainers |
| C-038 | Rule thresholds are selected on validation only with `K = ceil(B*N/10000)` and `score > threshold`; test labels never influence the threshold. | `scripts/rule_baselines.py`; `docs/RULE_BASELINES.md` | `docs/rule_baselines.json` (`thresholds`); `tests/test_rule_baselines.py` | unit tests; script loads test only after freezing thresholds | SUPPORTED | maintainers |
| C-039 | At 10 alerts/10k the best Tier A rule finds 1 of 286,957 attack flows; at 100 alerts/10k it finds 33. Tier A rule baselines are not a viable detector. | `docs/RULE_BASELINES.md`; `docs/PORTABLE_FEATURES.md` | `docs/rule_baselines.json` | artifact review; recompute from `counts` and `positives` | SUPPORTED | maintainers |
| C-040 | The per-flow SYN rule selects zero alerts because its top validation score is tied across 11,699 primary rows, more than either budget allows; `composite_packets_syn` inherits the tie (1,487 rows) and also selects zero validation alerts at 10/10k. | `docs/RULE_BASELINES.md`; `docs/PORTABLE_FEATURES.md` | `docs/rule_baselines.json` (`syn_tie_diagnostic`, `score_tie_diagnostics`) | artifact review; `tests/test_rule_baselines.py` | SUPPORTED | maintainers |
| C-041 | The preregistered P2B training partition (Monday-Tuesday) contains 0 volumetric/scan positives, so no supervised LogReg or Random Forest head can be fitted. | `docs/VOLUMETRIC_DETECTOR.md`; `docs/PHASE_STATUS.md` | `docs/VOLUMETRIC_MODEL.json` (`partitions.train`, `blocker`) | `venv/Scripts/python.exe scripts/volumetric_model.py ...`; artifact review | SUPPORTED | maintainers |
| C-042 | P2B created no model artifact or registry row and left the serving artifact and threshold unchanged. | `docs/VOLUMETRIC_DETECTOR.md` | `docs/VOLUMETRIC_MODEL.json` (`execution`, `artifact_identity`); `models/registry/registry.json` | artifact review; serving SHA-256 unchanged | SUPPORTED | maintainers |
| C-043 | The CIC-IDS-2017 day split confounds attack family with day and time: Wednesday validation positives are DoS-only, Friday test positives are DDoS/PortScan-only, and Wednesday's families occupy separate time windows. A time-ordered Wednesday amendment is therefore a family split, not a representative validation set. | `docs/P2B_PROTOCOL_ANALYSIS.md`; `docs/PHASE_STATUS.md` | `docs/p2b_protocol_analysis.json` (`family_day_matrix`, `wednesday_time_profile`, `half_split`, `expanding_folds`) | `venv/Scripts/python.exe scripts/p2b_protocol_analysis.py ...`; artifact review | SUPPORTED | maintainers |
| C-044 | The local external-data audit finds that UNSW-NB15 passes a leakage-safe group-split coverage gate for DoS and Reconnaissance after deduplication, but only 8/12 Tier A features are available. The complete 10-day CIC-IDS-2018 set has 12,079,420 unique feature-identical flows with DoS (231,486) and DDoS (775,955) but no PortScan; its temporal day split fails because positives sit in early days, and its group split covers DoS/DDoS only. | `docs/EXTERNAL_DATASET_AUDIT.md`; `docs/PHASE_STATUS.md` | `docs/EXTERNAL_DATASET_AUDIT.json` (`datasets.unsw_nb15`, `datasets.cic_ids_2018`) | `venv/Scripts/python.exe scripts/external_dataset_audit.py ...`; artifact review | SUPPORTED | maintainers |
| C-045 | CIDDS-002 supplies a leakage-safe temporal split with PortScan in all three partitions (150,533 train / 80,572 validation / 101,812 test attacker scan flows), but it is unidirectional NetFlow with 9/12 Tier A features and cannot validate the bidirectional serving model. | `docs/CIDDS002_AUDIT.md`; `docs/PORTABLE_FEATURES.md` | `docs/CIDDS002_AUDIT.json` (`audit.temporal_split`, `audit.schema`) | `venv/Scripts/python.exe scripts/cidds002_audit.py ...`; artifact review | SUPPORTED | maintainers |
| C-046 | P3 transfer is negative: the frozen Tier A model reaches ROC-AUC 0.7241 / AP 0.2048 on CIC-IDS-2018 and ROC-AUC 0.3793 / AP 0.1028 on UNSW-NB15. The strict frozen threshold (1.0) emits 0 alerts on both; at a label-free 100-alert/10k rank budget, recall is 2.34% (CIC-2018) and 0.73% (UNSW). | `docs/CROSS_DATASET.md`; `docs/PHASE_STATUS.md`; `docs/CROSS_DATASET_MAPPING.md` | `docs/cross_dataset_results.json`; `tests/test_cross_dataset_transfer.py` | `venv/Scripts/python.exe scripts/cross_dataset_transfer.py ...`; `venv/Scripts/python.exe -m pytest tests/test_cross_dataset_transfer.py -q` | SUPPORTED (negative result) | maintainers |
| C-047 | Scoped P2B on CIC-IDS-2018 covers DoS/DDoS only, with a leakage-safe group split (70/15/15), 5 seeds, 800k train cap, and validation-only thresholds. At 100 alerts/10k, logistic regression reaches 10.12% recall at 0.16% FPR; RF seed 42 reaches 0.02% because its uncalibrated validation scores saturate at 0.9999996753; isolation forest is near-random (ROC-AUC 0.49). PortScan is absent and not claimed. The serving artifact and threshold are unchanged. | `docs/P2B_SCOPED_EXTERNAL.md`; `docs/PHASE_STATUS.md` | `docs/p2b_scoped_external.json`; `tests/test_p2b_scoped_external.py` | `venv/Scripts/python.exe scripts/p2b_scoped_external.py`; `venv/Scripts/python.exe -m pytest tests/test_p2b_scoped_external.py -q` | SUPPORTED (negative/mixed result) | maintainers |
| C-048 | P3B replaces the 12 raw-scale Tier A inputs with 8 bounded ratios and log-scaled per-packet quantities while keeping the same CIC-IDS-2017 group split, external deduplication, and validation-only threshold policy. Both external ranking metrics improve: CIC-IDS-2018 ROC-AUC 0.7785 (was 0.7241), AP 0.2271 (was 0.2048); UNSW-NB15 ROC-AUC 0.4956 (was 0.3793), AP 0.1088 (was 0.1028). UNSW AP is only 0.0001 above its 10.8638% prevalence, and both validation budgets select threshold 1.000000, so strict external alerts are zero by construction. This is a research candidate; the serving artifact, frozen schema, and P3 row are unchanged. | `docs/PORTABLE_TRANSFER.md`; `docs/PHASE_STATUS.md` | `docs/portable_transfer_results.json`; `models/model_manifest_rf_portable_ratio_seed42.json`; `tests/test_portable_features.py` | `venv/Scripts/python.exe scripts/portable_transfer.py --cic-dir "C:/Users/varun/Downloads/CIC IDS 2018 Complete" --unsw-dir "C:/Users/varun/Downloads/UNSW_NB15"`; `venv/Scripts/python.exe -m pytest tests/test_portable_features.py -q` | SUPPORTED (ranking-only gain; absolute result weak) | maintainers |
| C-049 | Ingest accumulates scored flows per `(tenant, source IP, 5-minute window)`; an incident requires at least two of three capped signals and 70 risk points, so no single signal can open one. State is in-memory, tenant-scoped, and thread-safe. | `docs/MULTI_SIGNAL_EVIDENCE.md`; `GET /api/incidents` | `evidence_accumulator.py`; `tests/test_evidence_accumulator.py`; `tests/test_incidents_api.py` | `venv/Scripts/python.exe -m pytest tests/test_evidence_accumulator.py tests/test_incidents_api.py -q` | SUPPORTED (implementation behavior; detection efficacy unmeasured) | maintainers |
| C-050 | The optional Zeek `conn.log` parser reads TSV and JSON-lines logs, maps Tier A and portable features, and leaves `packet_length_max` unavailable rather than fabricating it. | `docs/ZEEK_COLLECTOR.md` | `zeek_parser.py`; `tests/test_zeek_parser.py`; `tests/fixtures/zeek_conn.log` | `venv/Scripts/python.exe -m pytest tests/test_zeek_parser.py -q` | SUPPORTED (parser behavior only; not validated live detection) | maintainers |
| C-051 | The DistriNet-corrected CIC-IDS-2017 CSV release is present locally: 5 daily files, 2,099,976 rows, 12/12 Tier A columns after the corrected-name mapping, and 4/4 portable inputs. Corrected label strings and Attempted categories differ from the original export. It is used only by the P3C strict-policy sensitivity run; no serving model consumes it. | `docs/DISTRINET_CICIDS2017_AUDIT.md` | `docs/DISTRINET_CICIDS2017_AUDIT.json`; `scripts/audit_distrinet_cicids2017.py` | `venv/Scripts/python.exe scripts/audit_distrinet_cicids2017.py --dir data/CICIDS2017_improved --zip data/CICIDS2017_improved.zip` | SUPPORTED (local provenance; CSVs are gitignored, not redistributed) | maintainers |
| C-052 | Under the strict frozen policy (case/spelling aliases only; every `- Attempted` and `Infiltration - Portscan` row excluded), the corrected CIC-IDS-2017 release keeps 2,008,410 of 2,099,976 rows at 21.2030% prevalence. The P3B portable model reaches grouped-test ROC-AUC 0.9988 / AP 0.9916 versus 0.9859 / 0.9297 on the original-Kaggle arm; test prevalence differs (19.0942% vs 21.2914%). Both validation budgets still select threshold 1.000000, so strict test alerts are zero by construction. The corrected release is also a CICFlowMeter re-extraction, so the difference is not attributable to labels alone. | `docs/CORRECTED_LABEL_SENSITIVITY.md`; `docs/DISTRINET_CICIDS2017_AUDIT.md` | `docs/corrected_label_sensitivity.json`; `scripts/corrected_label_sensitivity.py`; `tests/test_corrected_label_sensitivity.py` | `venv/Scripts/python.exe scripts/corrected_label_sensitivity.py --dir data/CICIDS2017_improved`; `venv/Scripts/python.exe -m pytest tests/test_corrected_label_sensitivity.py -q` | SUPPORTED (sensitivity; confounded by re-extraction; no external claim) | maintainers |

## Scope violation queries

Run these before any release that changes public copy:

```bash
git grep -nEi "general nids|detects all|zero-day|production-ready|production ready|all attacks|novel attack|deployment ready|9/10 detection|9/10 saas" -- \
  README.md docs/SCOPE_AND_CLAIMS.md docs/MODEL_CARD.md docs/PHASE_STATUS.md \
  templates/index.html templates/console.html templates/account.html templates/login.html
```

Every hit must be one of:

1. an explicit disclaimer,
2. a quoted disallowed term in a claim-audit table, or
3. removed.

## Change control

- Any change to the serving artifact, threshold, feature schema, or label space must update C-001–C-003 in the same change.
- Any new public claim must add a row with an artifact and a reproducible command.
- A phase may update only the rows it touches. Do not renumber existing rows.
- If a row becomes false, it is not deleted. It is marked UNSUPPORTED with the date and reason.
