# Privacy and Data Lifecycle Review (Phase S4)

**Status:** review of the current prototype behavior. Gaps are listed rather
than papered over.
**Date:** 2026-11-09.
**Boundary:** local/offline research prototype with an experimental capture
path. Not a hosted multi-tenant service.

This document compares what the code actually does with the product boundary in
`docs/PRODUCT_BOUNDARY_AND_THREAT_MODEL.md`. It does not assert GDPR, CCPA, HIPAA,
or any other compliance.

## 1. Data inventory

| Data | Where it lives | Sensitivity | Retention today | Deletion today |
|---|---|---|---|---|
| Raw uploads (CSV, PCAP, PCAPNG) | Request stream / temporary processing | Restricted | Request-scoped; no archive | Operator must remove any saved copy |
| Flow records (IPs, ports, protocol, label, attack flag, attack score) | `flow` table | Confidential; IP addresses can be personal data | Tenant `retention_days` (1–3650, default 30) | `POST /api/tenant/purge`; tenant deletion |
| S3 provenance (model version, artifact hash, schema, threshold, calibration) | `flow` table columns | Internal / integrity-critical | With parent flow | With parent flow |
| Review notes | `flow_reviews` | Confidential; free text may contain personal data | With parent flow | With parent flow |
| Review audit | `flow_review_audit` | Security-sensitive | With parent flow | With parent flow |
| Security audit events | `audit_events` | Security-sensitive | Tenant deletion only | Tenant deletion |
| Users (email, display name, password hash, role) | `users` table | Restricted | Until deprovisioned | Tenant deletion |
| Tenant configuration | `tenants` table | Confidential | Until tenant deletion | Tenant deletion |
| Application logs | Process/stdout | Must not contain payloads or secrets | Operator-configured | Operator-configured |
| External enrichment (public IP to AbuseIPDB) | Third party; local cache if enabled | Confidential | Provider policy / cache TTL | Not covered by tenant purge |
| Model artifacts and registry | `models/` | Internal / integrity-critical | Release lifetime | Not personal data |

## 2. Collection and purpose

- Flow metadata is collected to classify traffic and support analyst review.
- IP addresses, ports, protocol, timestamps, and prediction provenance are
  stored. Raw packet payloads are not stored by default.
- Review notes are analyst-authored. The product does not prevent an analyst
  from entering personal data into a note.
- AbuseIPDB enrichment is opt-in (`NETSHIELD_THREAT_INTEL_ENABLED`) and only
  public, valid IP addresses are eligible. Private addresses are skipped.
- There is no analytics, advertising, or cross-tenant profiling.

## 3. Retention

- Each tenant has `retention_days` (1–3650, default 30).
- `POST /api/tenant/purge` computes a cutoff, deletes older flows and their
  reviews, and writes a `tenant.retention_purge` audit event.
- There is no scheduler in the prototype. Purging is an operator action.
- Audit events are not purged by the retention window; they survive until
  tenant deletion.
- Uploaded files are not retained by the application, but an operator may save
  them outside the app. The product cannot enforce deletion of those copies.

## 4. Export

- `GET /api/flows/export` requires `flows:export` and is audited as
  `flows.export`.
- The CSV now includes model provenance columns: model version, artifact
  SHA-256, feature-schema version, threshold policy, threshold value,
  calibration version, decision basis, attack score, and argmax label.
- The export contains raw source/destination IP addresses and ports. There is
  no redaction, pseudonymization, or per-field access control.
- Anyone with `flows:export` can exfiltrate the tenant's flow metadata. Treat
  exported files as confidential and outside the retention controls.

## 5. Deletion

- `DELETE /api/tenants/<id>` requires platform-admin permission, a confirmation
  body matching the tenant slug, and refuses the default tenant.
- Tenant deletion removes flows, reviews, review audit, users, tenant-scoped
  audit rows, and the tenant row.
- **Not covered:**
  - database backups and point-in-time recovery copies;
  - object-storage copies or exported CSV files;
  - application and reverse-proxy logs;
  - the external enrichment provider's records;
  - local caches outside the database.
- There is no automated verification that a deletion removed every copy, and
  no documented restore-then-redelete procedure.

## 6. Access and tenancy

- Roles: `viewer`, `analyst`, `admin`, `platform_admin`.
- Flow, review, and audit queries are tenant-scoped; `tests/test_tenancy.py`
  exercises basic isolation.
- Platform administrators can cross tenant boundaries by design. That access is
  audited but not independently reviewed.
- OIDC SSO and TOTP MFA exist for the application, but there is no SAML, SCIM,
  password reset, session revocation, real IdP integration, or per-collector
  credential. Trusted-proxy SSO depends on a correctly configured reverse proxy
  and a shared secret.

## 7. Data-subject requests

There is no self-service request workflow. An operator would have to:

1. identify the tenant and the relevant flows by IP, port, or time range;
2. export or delete the rows manually through the API or database;
3. account for backups, logs, and exported files separately;
4. record the action in the audit log.

This is a manual, error-prone process. It is not a production data-subject
request capability.

## 8. Residency and third parties

- The operator chooses the database and its region. The application has no
  region pinning, residency control, or data-location metadata.
- AbuseIPDB is the only external data processor in the code. It receives a
  public IP address when enrichment is enabled. Its retention and jurisdiction
  are outside this repository's control.
- No other outbound data transfer is implemented.

## 9. Logging

- The structured logger is configured to emit event metadata, not payloads.
- Do not log raw flow dictionaries, headers, secrets, or review notes.
- Reverse-proxy and platform logs are outside the application's control and must
  be covered by the operator's retention and access policy.

## 10. Gaps that block handling customer data

1. Backups, object storage, and enrichment caches are not covered by deletion.
2. No scheduled retention job; purge is manual.
3. No deletion verification or restore-then-redelete test.
4. No self-service data-subject request workflow.
5. No residency control or data-location inventory.
6. Export has no redaction or per-field policy.
7. Audit history is not tamper-evident.
8. No managed secret store or key rotation.

These gaps are consistent with the product boundary: the prototype is suitable
for a controlled research demo, not for customer data.

## 11. Recommended next steps

1. Define backup retention and a restore-deletion procedure; test it.
2. Add a scheduled retention job with metrics and failure alerts.
3. Add deletion verification that counts rows across every store.
4. Decide whether flow metadata is personal data for the target deployment and
   document the legal basis.
5. Add export redaction options and a per-field policy.
6. Document the AbuseIPDB data-processing terms and cache TTL.
7. Re-review this document after any change to storage, logging, or enrichment.
