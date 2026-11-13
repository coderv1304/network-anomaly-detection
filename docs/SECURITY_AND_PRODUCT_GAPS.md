# Security and Product Readiness

## What this repository currently provides

- A Flask research application with batch file analysis, a SQLite-backed flow store, and a live capture console.
- A tenant-scoped flow/review/audit foundation with local users, roles, TOTP MFA, OIDC authorization-code SSO, trusted-proxy SSO, retention controls, and isolation tests (S1).
- S2 reliability controls: bounded ingest admission, rate limits, Prometheus metrics, JSON logs, and documented SLOs. The 20 flows/s ingest latency SLO now passes after batch inference, removal of per-row refresh queries, and SQLite WAL tuning; capacity above 20 flows/s was not re-measured.
- S3 model registry and deployment gate: every stored prediction records model version, artifact SHA-256, feature schema, threshold policy, and calibration version; promotion, tested rollback, schema-mismatch refusal, and a startup artifact check are implemented.
- S4 security evidence: dependency and filesystem scans, a CycloneDX SBOM, a secret scan, a built and scanned serving image, and a CI gate. Runtime requirements have zero advisories and the image has zero critical, zero Python, and zero fixable findings; 186 unfixed Debian OS advisories remain accepted baseline risk, and the external penetration test is blocked.
- S5 operations documentation: an [operations runbook](OPERATIONS_RUNBOOK.md), [staging/migration guidance](STAGING_AND_MIGRATIONS.md), and [incident-response plan](INCIDENT_RESPONSE.md) cover environments, configuration, release checks, Alembic migrations, health/readiness, rollback, and incident playbooks. A local SQLite backup/restore drill passes with counts, logical SHA-256, and `PRAGMA integrity_check`, and an AES-256-GCM drill passes with authenticated restore and an off-host-directory hash check. A `staging` profile, Alembic baseline, startup revision guard, and `scripts/preflight.py` exist. There is still no IaC, no operated staging environment, no production migration history, no operated off-host storage, no site-measured RPO/RTO, and no incident drill.
- S6 onboarding and commercial status: a [developer onboarding and support note](ONBOARDING_AND_SUPPORT.md) documents a best-effort support path and states explicitly that the project is **not commercial**, with no customers, price, SLA, billing, or usage metering.
- Configurable API-key checks for ingestion and production/staging-mode login, session, cookie, database, and rate-limit checks.
- A standalone experimental capture path and an optional third-party AbuseIPDB lookup.
- Local development/container configuration intended for a controlled demo.

These controls reduce accidental exposure in the prototype. They do **not** make it a production multi-tenant SaaS service or establish compliance with a security standard.

## Current release boundary

Do not onboard real customers or expose this service directly to the public internet until the gaps below are addressed and independently reviewed.

### Identity, authorization, and tenancy

- S1 adds local users, roles (`viewer`, `analyst`, `admin`, `platform_admin`), tenant-scoped queries, append-only application audit events, retention controls, and isolation tests. It also adds TOTP MFA with encrypted secrets and hashed single-use recovery codes, plus an OIDC authorization-code client with PKCE and RS256 ID-token verification. It does not add SAML, SCIM provisioning, password reset, session revocation, or per-collector credentials. OIDC has been tested only against a local fake provider, not a real IdP tenant.
- Current production login supports the legacy configured administrator password hash, local users in the `users` table, TOTP MFA for local users, and OIDC SSO. Trusted-proxy SSO remains a header-based shim that depends on a correctly configured reverse proxy; it is deprecated in favor of OIDC.
- Data models and flow/review/audit queries now carry `tenant_id`, and `tests/test_tenancy.py` proves basic read/write isolation. This is a foundation, not proof of enterprise isolation: shared-database operator access, backup isolation, and cross-tenant support workflows still need review.
- The production service key is restricted to `POST /api/flows` and must be sent in `X-API-Key`; it cannot read flow APIs or edit reviews. The bundled PyFlowMeter sender is explicitly local-demo-only because it cannot send headers and would expose a query-string key. Production still needs an enrolled, TLS-protected collector with a scoped credential.
- Audit history exists as an append-only application table, but it is not tamper-evident, hash-chained, WORM-backed, or independently monitored. Credential rotation/revocation and privileged support access workflows remain incomplete.
- Socket.IO authorization now uses the resolved identity, but tenant-aware channel isolation has not been load-tested.

### Data lifecycle and service architecture

- SQLite and in-process state are suitable only for local research; production and staging reject SQLite and use PostgreSQL. The schema is versioned with Alembic (baseline `f68710d807f3`), and staging/production startup fails closed unless the database is at the code revision. Development still uses `create_all()` plus idempotent additive helpers. Local and encrypted backup drills pass, but the encrypted copy is not operated off-host and no site-measured RPO/RTO is defined.
- Raw uploads, flow records, logs, and backups need explicit retention, deletion, residency, and access policies.
- The web process should not own packet capture. A separately enrolled customer-side collector should send authenticated, encrypted, outbound telemetry to a control plane.
- S2 implements bounded ingest admission with HTTP 503 + `Retry-After`, per-route rate limits, metrics, and JSON logs. A durable queue, idempotency keys, worker isolation, and parser resource limits are still required before high-volume use.

### Security engineering and operations

- Enforce TLS at a trusted ingress; use managed secrets and key rotation. Add structured audit events and security monitoring.
- S4 produced dependency scans (`pip-audit`, Trivy), a CycloneDX SBOM, a secret scan, a runtime/development requirements split, and a built and scanned serving image. A checked-in CI workflow runs the scans behind `scripts/security_gate.py`, which fails on critical, fixable, secret, and failed-misconfiguration findings; the workflow has not yet run on the repository host. Runtime requirements have zero advisories and the image has zero critical, zero Python, and zero fixable findings. Still required: an external penetration test, a real IdP integration, managed secrets with rotation, a defined vulnerability response and base-image refresh process, backup/restore deletion coverage, and a tamper-evident audit log.
- Use an ASVS control map and NIST CSF/SSDF as engineering references. These are not certifications. Make no SOC 2 or ISO 27001 claim unless completed and correctly scoped.
- Define and measure ingestion latency, availability, data loss, recovery objectives, and capture-gap alerting. Backup restoration has been exercised locally and passes ([result](backup_restore_drill.json)); incident response is documented but has **not** been drilled, and no RPO/RTO or off-host recovery exists.

### Detection quality and analyst workflow

- Keep batch results and synthetic telemetry labeled as model predictions or simulations.
- Link every prediction to model/schema versions and the actual features used. S3 now stores model version, artifact SHA-256, feature schema, threshold policy, threshold value, calibration version, decision basis, attack score, and the argmax label on every stored prediction and CSV export. Do not present uncomputed explanations, enrichment, severity, or threat attribution as evidence.
- The local prototype now persists review status, freeform notes, and a per-flow change history for stored records. It has no assignment workflow, reason taxonomy, tenant-aware actor identity, retention policy, or production-grade immutable audit storage; do not equate this with a SOC workflow.
- Keep any response in dry-run or human-approved mode with customer-controlled policy, rollback, and an auditable action record.
- Validate day/environment holdouts, feature parity, calibration, class-specific performance, and a second dataset before making efficacy claims. D4 and D5 evaluate threshold transfer and isotonic calibration on the Random Forest configuration that is now served. The serving entry remains explicitly uncalibrated because the available isotonic artifact fails the ECE gate, so the UI must not show a confidence percentage.
- D6 tested seven rare/unseen-family arms across five seeds and found no arm that reaches Bot recall ≥0.50 at ≤1% FPR. D9 published a cost-sensitive release gate and it fails on FPR, alert rate, Bot recall, calibration, external data, pilot, and site cost model; artifact identity and five-seed reporting pass. S7 is pre-registered but **not run**; there is no design partner or pilot data. The S8 release gate is implemented and machine-checked; it currently fails or is blocked on detection, external review, and a real pilot. See [UNSEEN_FAMILY_AND_BOTNET.md](UNSEEN_FAMILY_AND_BOTNET.md), [COST_MODEL_AND_RELEASE_GATE.md](COST_MODEL_AND_RELEASE_GATE.md), [S7_PILOT_OUTCOME.md](S7_PILOT_OUTCOME.md), and [S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md](S8_EXTERNAL_REVIEW_AND_RELEASE_GATE.md).

## Suggested delivery sequence

1. **Research credibility:** extend evaluation with held-out evidence, a second dataset, and paired feature parity. Serving/evaluation artifact identity is now closed.
2. **Single-tenant pilot:** real OIDC integration, secure collector enrollment, managed database, retention/deletion, audit log, isolated processing, and monitoring. Local MFA and an OIDC client exist; the pilot still needs a real IdP and a design partner.
3. **Multi-tenant SaaS:** tenant-aware authorization at every data access, isolation tests, billing/quotas, SLOs, disaster recovery, and independent penetration testing.
4. **Assurance:** maintain control evidence and determine buyer-specific SOC 2 or ISO 27001 scope; certification is a separate program.
