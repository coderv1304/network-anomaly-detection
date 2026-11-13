# Product Boundary and Threat Model (Phase S0)

**Status:** current product boundary for the prototype.
**Date:** 2026-11-08.
**Rule:** a feature that crosses a boundary in this document needs an explicit update to this document and the tenancy/security tests.

## 1. Product boundary

NetShield is **hybrid, offline-first, with an experimental live-capture path**:

- The supported, testable path is offline: authorized flow CSV, PCAP, or PCAPNG files are analyzed in the local Flask application.
- The console at `/` is a real product surface over stored flow records and capture status. It polls every two seconds.
- Local packet capture is **disabled by default**. It requires `ENABLE_LOCAL_CAPTURE=true`, a valid interface, capture privileges, and PyFlowMeter. It is not a validated sensor.
- The Go capture program is a standalone prototype. It does not implement the Python model's complete feature schema and does not connect directly to the inference API.
- There is no hosted multi-tenant service, no billing, no on-call rotation, and no external SLA.

### What the product does

- Accepts flow records and packet captures.
- Applies a locally loaded classification artifact.
- Stores predicted labels and review state.
- Exposes stored records through a browser console and read/write API.
- Provides tenant-scoped access, roles, audit events, and retention controls as a foundation.
- Optionally enriches eligible public IP addresses through AbuseIPDB.

### What the product explicitly does not do

- It does not confirm an incident or attribute an actor.
- It does not block hosts, change firewalls, or execute containment.
- It does not send Slack, PagerDuty, AWS, Cloudflare, or TAXII actions.
- It does not detect arbitrary zero-day attacks.
- It does not provide validated threat intelligence.
- It does not claim that live-capture features match the training pipeline.
- It does not provide a real IdP integration, SAML/SCIM, enterprise tenancy, or a penetration-tested service. TOTP MFA and an OIDC client exist but are not operated evidence.
- It does not store raw packet payloads by default; batch PCAP parsing produces flow records, not a packet archive.

## 2. Data classification

| Data | Examples | Sensitivity | Storage | Default retention |
| --- | --- | --- | --- | --- |
| Raw capture files | PCAP, PCAPNG, flow CSV uploads | **Restricted** | Upload path / temporary processing | Request-scoped; operator must delete |
| Flow records | IPs, ports, protocol, predicted label, attack flag | **Confidential** | `flow` table | Tenant `retention_days` (default 30) |
| Review notes | Analyst status and free-text note | **Confidential**, may contain personal data | `flow_reviews` | With parent flow |
| Review audit | Actor, status change, note-change flag | **Security-sensitive** | `flow_review_audit` | With parent flow |
| Security audit | Login, read, export, review, admin, retention events | **Security-sensitive** | `audit_events` | Tenant deletion only, except explicit purge policy |
| User credentials | Password hash, email, role | **Restricted** | `users` | Until deprovisioned |
| Tenant configuration | Slug, name, retention policy | **Confidential** | `tenants` | Until tenant deletion |
| Model artifacts | Pickles, manifests, hashes | **Internal / integrity-critical** | `models/` | Release lifetime |
| Feature schema | Feature names and order | **Internal** | Artifact / manifests | Release lifetime |
| Optional enrichment | Public IP sent to AbuseIPDB | **Confidential** | Not stored beyond cache | Cache TTL |

### Handling rules

- Never put raw packet payloads, credentials, or full audit detail in logs.
- Do not send private or invalid IP addresses to AbuseIPDB.
- Do not use review notes for unrelated personal data.
- Treat flow metadata as sensitive even when payloads are absent: IP addresses and ports can reveal user behaviour.
- Model artifacts are integrity-critical. A modified artifact is a security incident, not a model update.

## 3. Actors

| Actor | Description | Trust |
| --- | --- | --- |
| Tenant viewer | Read-only console/API user | Authenticated, least privilege |
| Tenant analyst | Reads flows, reviews alerts, exports data | Authenticated, may change review state |
| Tenant admin | Manages users, retention, tenant settings | Authenticated, high privilege |
| Platform admin | Creates/deletes tenants, cross-tenant administration | Highest privilege, audited |
| Collector service | `X-API-Key` ingest-only client | Write-only, no read access |
| Trusted reverse proxy | Supplies SSO identity headers | Trusted only when shared secret matches |
| External enrichment provider | AbuseIPDB | Third party, receives eligible public IPs only |
| Network attacker | Sends malicious or spoofed traffic | Untrusted |
| Unauthenticated user | Browser or API client without credentials | Untrusted |

## 4. Trust boundaries

```text
Untrusted network
      │
      ▼
[Reverse proxy / TLS termination] ── trusted-proxy SSO boundary
      │
      ▼
[Flask application] ── session / CSRF / RBAC / tenant scoping
      │        │
      │        ├──> [SQLite or managed Postgres] ── tenant_id on every row
      │        ├──> [Model artifact files] ── hash verification in production
      │        └──> [AbuseIPDB] ── optional public-IP disclosure boundary
      │
      ▼
[Collector / local capture] ── X-API-Key ingest boundary
```

Boundaries that matter:

1. **Browser to application:** session cookie, CSRF token, security headers, rate limits.
2. **Collector to application:** header-only service key, ingest-only permission, tenant selection.
3. **Application to database:** every tenant-owned query must include `tenant_id`.
4. **Application to model files:** artifact hash must match the release manifest in production.
5. **Application to external enrichment:** only eligible public IPs cross this boundary, and only when enabled.
6. **Proxy to application:** SSO headers are trusted only when `NETSHIELD_PROXY_SHARED_SECRET` matches and the proxy strips client-supplied copies.

## 5. Top threats and controls

| Threat | Impact | Current controls | Residual risk |
| --- | --- | --- | --- |
| Cross-tenant read via a missing `tenant_id` filter | Confidentiality breach | `tenant_scoped()` helper on flow, review, stats, snapshot, audit, and user queries; isolation tests | A future route can forget the helper. Code review and tests are required. |
| Cross-tenant write via guessed flow ID | Integrity breach | `tenant_scoped(Flow).filter(...).first_or_404()` on reads and reviews | Shared database operators can still bypass application controls. |
| Artifact tampering or wrong artifact loaded | False predictions, supply-chain risk | `MODEL_SHA256` verification in production; manifest and serving hash display | Development can load legacy artifacts without a hash. No signed-artifact registry yet. |
| Credential compromise | Account takeover | Password hashing, login rate limit, session expiry, CSRF, audit events; TOTP MFA for local accounts; OIDC SSO | No password-reset flow, no breached-password check, and no real IdP integration. |
| Trusted-proxy header spoofing | Identity forgery | Shared-secret comparison; proxy must strip client headers | If the app is exposed directly, headers can be forged unless the secret is strong and the proxy is the only ingress. |
| Service-key leakage | Unauthorized ingest / data poisoning | Header-only key, ingest-only permission, rate limit, audit of batch ingest | Key rotation is manual; no per-collector key or revocation UI. |
| Retention violation | Data kept longer than policy | Tenant `retention_days`; explicit purge endpoint; audit event | No scheduled purge worker; purge is operator-triggered. |
| Tenant deletion leaving derived data | Privacy and contractual breach | Explicit deletion of flows, reviews, review audit, users, and audit rows; confirmation by slug; audit event | Backups and external copies are out of scope; no backup-isolation test. |
| Audit-log tampering | Loss of accountability | Append-only model; no update/delete route; admin-only read | Database operators can modify rows. No hash chain or WORM storage. |
| Sensitive data in logs | Confidentiality breach | Error handlers avoid dumping flow bodies; audit detail is bounded | Application and proxy logs still need review. |
| AbuseIPDB over-disclosure | Privacy breach | Public-IP eligibility check; opt-in configuration; cache | Third-party retention is outside NetShield's control. |
| Denial of service / queue overload | Availability loss | Rate limits; batch size cap; polling endpoint | No measured backpressure, SLO, or load test yet. |
| Model mismatch between serving and evaluation | False product claims | Scope document; serving artifact metadata; threshold-applied flag | Mitigated: the registry-active serving artifact and the evaluated seed 42 manifest have the same SHA-256. A registry/deployment gate refuses a mismatch. |
| Unvalidated live features | False confidence in live predictions | Console data-boundary bar; parity warning; capture disabled by default | Upload path covers 80/80 features, but the live path drops ICMP/IPv6 and numeric disagreement remains. |

## 6. Identity and access model

Roles implemented in S1:

| Role | Read flows | Review | Export | Audit | Manage users | Retention | Manage tenants |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `viewer` | Yes | No | No | No | No | No | No |
| `analyst` | Yes | Yes | Yes | Yes | No | No | No |
| `admin` | Yes | Yes | Yes | Yes | Yes | Yes | No |
| `platform_admin` | Yes | Yes | Yes | Yes | Yes | Yes | Yes |

Authentication modes:

- **Local password login** against the `users` table, with optional TOTP MFA.
- **OIDC SSO** authorization-code flow with PKCE and RS256 ID-token verification when configured.
- **Legacy administrator password** from `NETSHIELD_ADMIN_PASSWORD_HASH` for existing deployments.
- **Trusted-proxy SSO** via `X-NetShield-User` plus `X-NetShield-Proxy-Secret` when enabled.
- **Development mode** uses an explicit local administrative identity and must never be exposed publicly.

Not implemented: a real IdP integration test, SAML, SCIM provisioning, password reset, session revocation, per-collector keys, and hardware-backed secrets. OIDC has been tested only against a local fake provider.

## 7. Retention and deletion policy

- Each tenant has `retention_days` (1–3650; default 30).
- `POST /api/tenant/purge` deletes flows older than the cutoff and their review rows, then writes an audit event.
- `DELETE /api/tenants/<id>` requires platform-admin permission and a body containing `{"confirm": "<slug>"}`.
- Tenant deletion removes flows, reviews, review audit, users, tenant-scoped audit rows, and the tenant row.
- The default tenant cannot be deleted.
- Backups, object-storage copies, and external enrichment caches are **not** covered by tenant deletion in this prototype.
- A production design needs scheduled retention, backup isolation, legal hold, and deletion verification.

## 8. Security non-goals for this phase

S0 does not add features. It defines the boundary that later phases must test. In particular:

- No full SSO/OIDC implementation.
- No penetration test.
- No SBOM or dependency-scanning gate.
- No SLO, on-call, or load test.
- No model registry with signed artifacts and rollback.
- No billing or commercial onboarding.
- No claim of multi-tenant SaaS readiness.

## 9. Review checklist

Before any release that touches tenancy or identity:

1. Every tenant-owned query uses `tenant_scoped()` or an explicit tenant filter.
2. Isolation tests create two tenants and prove read and write separation.
3. Service-key ingest cannot read customer data.
4. Review and admin routes require the correct permission.
5. Audit events are written for login, read, export, review, admin, retention, and tenant deletion.
6. Retention purge deletes derived review rows.
7. Tenant deletion requires confirmation and removes tenant-owned rows.
8. The console still distinguishes `Live`, `Stored`, and `Demo`.
9. The scope document is updated if a claim changes.
