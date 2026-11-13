# S8 — External Review and Release Gate

**Status:** **gate implemented; verdict FAIL.** The external security/readiness review is **not commissioned**, and the machine-checked release gate does not pass. No 9/10 detection or SaaS-readiness claim is allowed.
**Date:** 2026-11-11.
**Machine-readable verdict:** [`s8_release_gate.json`](s8_release_gate.json).
**External-review record:** [`s8_external_review.json`](s8_external_review.json) — status `not_commissioned`.
**Gate script:** `scripts/release_gate.py`.
**Tests:** `tests/test_release_gate.py`.

## 1. What this phase does and does not do

S8 is the final, adversarial gate. It has two parts:

1. **Preparation** — assemble the evidence an external reviewer needs, define the review scope, and make every release condition machine-checkable.
2. **External review** — an independent reviewer examines the product and signs a report.

This repository now does (1). It cannot do (2): the assistant cannot commission, perform, or sign an independent review. The review record therefore stays `not_commissioned`, and the gate stays **FAIL/BLOCKED**.

**Do not describe this document as a security certification, an audit opinion, a penetration-test report, or a release approval.** It is the gate and the evidence index that a real reviewer would use.

## 2. Current gate result

Run:

```bash
venv/Scripts/python.exe scripts/release_gate.py --json docs/s8_release_gate.json
```

Current output: **FAIL**, with 9 checks: 6 pass, 1 fail, 2 blocked.

| # | Check | Requirement | Current status | Why |
| --- | --- | --- | --- | --- |
| 1 | `detection_gate` | D9 cost-sensitive detection gate passes every check | **FAIL** | 7 of 9 D9 checks fail: FPR, alert rate, Bot recall, calibration, external dataset, pilot, site cost model. Artifact identity and five-seed reporting pass. |
| 2 | `artifact_identity` | Served artifact is the evaluated and gated artifact | **PASS** | Registry-active `serving-rf-day-based-seed42-v1` has the same SHA-256 as the evaluated seed 42 manifest; the deployment check passes. |
| 3 | `security_gate` | No critical, fixable, secret, or failed-misconfiguration findings | **PASS** | 0 critical, 0 fixable, 0 secrets, 0 failed misconfigurations. 186 unfixed Debian OS advisories remain accepted baseline risk. |
| 4 | `secret_scan` | No secrets in tracked or untracked non-ignored files | **PASS** | 0 findings across 281 tracked and untracked non-ignored files. Git history and ignored environment files are still not covered. |
| 5 | `external_review` | Independent review completed, critical/high findings closed | **BLOCKED** | No reviewer has been engaged. See [`s8_external_review.json`](s8_external_review.json). |
| 6 | `prospective_pilot` | Real human-review pilot completed against predeclared criteria | **BLOCKED** | No design partner and no real pilot data. The S7 self-test is synthetic and is rejected by the gate. |
| 7 | `slo_compliance` | Ingest p95 ≤ 250 ms at 20 flows/s with ≥ 99.5% success | **PASS** | The latest run measured p95 164.9 ms with 100% success after batch inference, removal of per-row refresh queries, and SQLite WAL tuning. Capacity above 20 flows/s was not re-measured. |
| 8 | `backup_restore` | Local and encrypted backup/restore drills pass integrity and count checks | **PASS** | The local SQLite drill passes, and the gate also requires the AES-256-GCM drill to pass with authenticated restore and an off-host-directory hash check. Operated off-host durability and site RPO/RTO remain unproven. |
| 9 | `sbom` | CycloneDX SBOM exists with components | **PASS** | 29 components recorded. |

**Verdict: FAIL. Detection stays 4/10. Production SaaS stays 3/10.**

## 3. Evidence package for an external reviewer

Provide these artifacts, in this order. Every path is in the repository unless marked external.

| Evidence | Path | What the reviewer should check |
| --- | --- | --- |
| Product boundary and threat model | [`PRODUCT_BOUNDARY_AND_THREAT_MODEL.md`](PRODUCT_BOUNDARY_AND_THREAT_MODEL.md) | Data classes, trust boundaries, top threats, explicit non-goals. |
| Tenancy and access control | [`TENANCY_AND_ACCESS_CONTROL.md`](TENANCY_AND_ACCESS_CONTROL.md), [`STAGING_AND_MIGRATIONS.md`](STAGING_AND_MIGRATIONS.md) | Query-layer scoping, roles, SSO mode, MFA, audit log, retention/deletion, migration guard. |
| Isolation and identity tests | `tests/test_tenancy.py`, `tests/test_sensor_identity.py`, `tests/test_mfa.py`, `tests/test_oidc.py` | Cross-tenant read, write, review, summary, and filter attempts; TOTP replay/lockout; OIDC state/nonce/PKCE/signature checks. |
| Audit samples | `GET /api/audit`, `GET /api/flows/<id>/review/audit` | Append-only events, actor, tenant, outcome, timestamps. |
| SLOs and load test | [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md), [`load_test_results.json`](load_test_results.json) | Declared targets vs measured p95, success ratio, backpressure point. |
| Model provenance | [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md), [`EVIDENCE_PACKAGE.md`](EVIDENCE_PACKAGE.md) | Artifact hash, schema, threshold policy, calibration version, rollback. |
| Detection evidence | [`COST_MODEL_AND_RELEASE_GATE.md`](COST_MODEL_AND_RELEASE_GATE.md), [`EVALUATION_PROTOCOL_V2.md`](EVALUATION_PROTOCOL_V2.md) | Frozen splits, per-family metrics, threshold transfer, failed gates. |
| External validation | [`EXTERNAL_VALIDATION.md`](EXTERNAL_VALIDATION.md) | Why no second dataset exists; what the 11-flow capture does and does not show. |
| Pilot | [`S7_PILOT_PREREGISTRATION.md`](S7_PILOT_PREREGISTRATION.md), [`S7_PILOT_OUTCOME.md`](S7_PILOT_OUTCOME.md) | Criteria written before data; outcome is “not run”. |
| Incident response | [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md), [`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md) | Playbooks, escalation, restore, rollback. |
| Security evidence | [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md), [`SECURITY_FINDINGS.json`](SECURITY_FINDINGS.json) | Scans, SBOM, accepted risks, open items. |
| Penetration-test plan | [`PENETRATION_TEST_PLAN.md`](PENETRATION_TEST_PLAN.md) | Scope and rules of engagement for the external test. |
| Release gate | [`s8_release_gate.json`](s8_release_gate.json) | The exact pass/fail state at the time of review. |

### 3.1 Rules of engagement

- Test only a disposable deployment with synthetic or approved data.
- Do not test a live customer tenant or production credentials.
- Report every finding with severity, reproduction, impact, and owner.
- Critical and high findings block release until closed and retested.
- Medium and low findings need a tracked owner and target date.
- The reviewer signs the report and states its scope and limitations.

## 4. Findings-to-closure process

1. The reviewer records each finding in a tracker with a stable ID.
2. Engineering assigns an owner and target date.
3. A fix includes a regression test or a documented compensating control.
4. The reviewer retests the finding and marks it closed.
5. `docs/s8_external_review.json` is updated with `status`, `critical_open`, `high_open`, and the report path.
6. `scripts/release_gate.py` is re-run. The gate passes the external-review check only when `status == "completed"` and no critical/high findings remain open.

The gate does not accept prose. A finding is closed only when the machine-readable record says so.

## 5. What would change the scores

The gate is intentionally hard to pass. A 9/10 detection claim would require, at minimum:

- the served artifact is the evaluated artifact;
- FPR ≤ 1% on every day and seed;
- alert rate ≤ 2% of flows;
- Bot recall ≥ 0.50 at ≤ 1% FPR;
- ECE ≤ 0.05 on held-out data;
- a second independent dataset;
- a completed human pilot;
- a site-supplied cost model.

A 9/10 SaaS claim would require, at minimum:

- an external review with no open critical/high findings;
- managed secrets, a real IdP integration, and full SSO;
- sustained SLO compliance (the current evidence is one 20 flows/s run);
- off-host encrypted backup with measured RPO/RTO;
- an operated staging environment and a production migration history;
- a real pilot with measured onboarding, yield, analyst time, and support load.

None of these is satisfied today. **The scorecard does not move because this document exists.**

## 6. Reproduction and CI

```bash
# Aggregate all release evidence and write the verdict.
venv/Scripts/python.exe scripts/release_gate.py --json docs/s8_release_gate.json

# Run the gate tests.
venv/Scripts/python.exe -m pytest tests/test_release_gate.py -q

# Supporting gates.
venv/Scripts/python.exe scripts/deployment_check.py --json
venv/Scripts/python.exe scripts/security_gate.py --report docs/trivy_image.json --json docs/security_gate.json
venv/Scripts/python.exe scripts/secret_scan.py --json docs/secret_scan.json
```

The script exits `0` only when all nine checks pass. It exits `1` for FAIL or BLOCKED. It never edits evidence and never treats a missing file as a pass.

## 7. Limitations

- The gate is only as good as the evidence files it reads. A passing file can still be stale; check the `generated_at` fields.
- The security gate covers the built image and tracked tree, not git history, runtime configuration, or the host.
- The local backup drill passes, and a separate encrypted drill proves AES-256-GCM encryption plus authenticated restore. Neither proves operated off-host durability, key custody, or a site-declared RPO/RTO.
- The SLO check uses one load-test run, not a sustained window.
- The external-review record is a placeholder for an independent review, not a substitute for one.
- The gate cannot detect a dishonest claim made outside the repository.

## 8. Verdict

**S8 preparation is complete; the external review is not commissioned; the release gate is FAIL/BLOCKED. No 9/10 detection or SaaS-readiness claim is allowed.**
