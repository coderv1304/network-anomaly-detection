# External Penetration Test Plan (Phase S4)

**Status: NOT PERFORMED / BLOCKED.**
No independent penetration test has been commissioned, scoped with a vendor, or
executed. An internal automated assessment (ZAP baseline, Bandit, Trivy) was run
and is documented in section 9; it is not a penetration test. This document is
the plan an independent tester would use. It is not evidence that a test
happened.

Do not describe NetShield as "penetration-tested", "security-reviewed by a third
party", or "enterprise-ready" until the exit criteria in section 8 are met.

## 1. Objective

Find exploitable weaknesses in the research prototype before any customer pilot,
with priority on:

- authentication and session handling;
- tenant isolation and authorization;
- the ingest and upload attack surface;
- the model-artifact and deployment boundary;
- data retention, export, and deletion behavior.

## 2. Target and environment

| Item | Value |
|---|---|
| Target | NetShield Flask application and its REST/Socket.IO API |
| Environment | Isolated staging deployment with synthetic data; never production customer data |
| Build | Exact commit under test plus the container image digest |
| Entry points | Web UI (`/`, `/research`), REST API (`/api/*`), Socket.IO, ingest (`POST /api/flows`) |
| Identity modes | Local login, legacy admin hash, trusted-proxy SSO header mode |
| Data | Synthetic flow records only; no real customer or personal data |
| Out of scope | AbuseIPDB itself, the underlying cloud/provider, the CIC-IDS-2017 dataset, the Go capture prototype unless separately scoped |

## 3. Rules of engagement

- Written authorization naming the target, time window, and test accounts.
- No denial-of-service testing against shared infrastructure; resource-exhaustion
  tests are coordinated and rate-limited.
- No destructive deletion of the staging database without a snapshot.
- Stop and report immediately on any evidence of real data exposure.
- Test accounts: viewer, analyst, admin, platform admin, and a service ingest key.
- All findings reproduced with request/response evidence and a severity.
- Tester must not retain copied data after the engagement.

## 4. Threat model summary

Assets: flow metadata (IPs, ports, predictions), review notes, audit history,
user credentials, model artifacts, tenant configuration.

Adversaries:

- unauthenticated internet user;
- authenticated low-privilege tenant user;
- malicious or compromised collector;
- tenant administrator attempting cross-tenant access;
- supply-chain attacker modifying a dependency or model artifact.

## 5. Test cases

### Authentication and session

- Credential stuffing and brute-force resistance; rate limits on `/login`.
- Session fixation, cookie flags (`Secure`, `HttpOnly`, `SameSite`), rotation on
  login/logout, idle and absolute timeout.
- CSRF protection on state-changing browser routes.
- Trusted-proxy SSO header spoofing when the proxy secret is absent, wrong, or
  replayed.
- Development-mode identity leakage when `NETSHIELD_ENV` is misconfigured.

### Authorization and tenancy

- Horizontal privilege escalation: tenant A reads, reviews, exports, or deletes
  tenant B's flows by ID or filter.
- Vertical escalation: viewer/analyst reaching admin or platform-admin routes.
- IDOR on `/api/flows/<id>`, review updates, audit reads, retention, user
  management, and tenant deletion.
- Socket.IO channel isolation between tenants.
- Service key scope: confirm it can ingest but cannot read, review, export, or
  administer.

### Input handling

- SQL injection and ORM filter injection in list/export/review parameters.
- Stored XSS in review notes, flow fields, and any rendered error.
- CSV formula injection in exports.
- Path traversal in upload handling and static file serving.
- PCAP/PCAPNG parser abuse: malformed packets, deep nesting, decompression
  bombs, CPU/memory exhaustion, and crash handling.
- JSON body limits, batch size limits, and type confusion on ingest.
- SSRF or data exfiltration through the AbuseIPDB enrichment path.

### Transport and headers

- TLS configuration and HSTS at the ingress.
- CSP, `X-Content-Type-Options`, `X-Frame-Options`/frame-ancestors, referrer
  policy, and permissions policy.
- CORS and Socket.IO origin allowlist behavior.
- Error responses that leak stack traces, paths, or configuration.

### Model and deployment boundary

- Replace the serving artifact and confirm startup fails the registry check.
- Tamper with a registry entry and confirm hash/signature verification fails.
- Present an artifact with a different feature schema and confirm refusal.
- Attempt to activate an unapproved or retired version.
- Confirm the console does not display an uncalibrated confidence value.
- Confirm stored predictions carry model version, artifact hash, schema,
  threshold policy, and calibration version.

### Privacy and lifecycle

- Export permission and audit behavior.
- Retention purge correctness and audit event.
- Tenant deletion completeness, including reviews and audit rows.
- Confirm backups, logs, and caches are documented as out of scope.
- Confirm review notes and IP addresses are not written to logs.

### Supply chain

- Dependency confusion and typosquatting review.
- SBOM completeness against the built image.
- Container image scan and base-image currency.
- Secret leakage in image layers, build args, and CI logs.

## 6. Deliverables

1. Executive summary with a risk rating.
2. Findings with severity (CVSS v3.1 or v4.0), reproduction steps, evidence,
   affected component, and remediation.
3. Retest results after fixes.
4. A statement of scope, limitations, and test window.

## 7. Severity and remediation targets

| Severity | Target |
|---|---|
| Critical | Fix or disable the affected path immediately; block release |
| High | Fix before any pilot; retest |
| Medium | Fix or formally accept with a dated owner before pilot |
| Low | Schedule; document acceptance |

## 8. Exit criteria

The engagement is complete only when:

- the agreed scope was tested;
- every critical and high finding is fixed and retested, or the release is
  blocked;
- medium findings have an owner and a dated remediation or acceptance;
- the final report and retest letter are stored with the release evidence;
- this document is updated with the vendor, dates, scope, and report location.

## 9. Internal automated assessment (not a penetration test)

An internal assessment was run against the built serving image. It is recorded
here so the gap between "automated checks" and "independent test" is explicit.

| Check | Tool | Result | Evidence |
|---|---|---|---|
| Unauthenticated HTTP baseline | OWASP ZAP baseline | 0 FAIL, 4 WARN, 64 PASS | `docs/zap/zap_report.{json,md,html}` |
| Python static analysis | Bandit 1.7.9 | 0 HIGH, 0 MEDIUM, 5 LOW | `docs/bandit_report.json` |
| Container image scan | Trivy 0.76.1 | 0 CRITICAL, 0 Python, 0 fixable; 186 unfixed OS baseline | `docs/trivy_image.json` |
| Actionable-findings gate | `scripts/security_gate.py` | PASS | `docs/security_gate.json` |
| Secret scan | custom + Trivy | 0 findings in tracked and untracked non-ignored files | `docs/secret_scan.json` |
| Dependency audit | pip-audit | 0 runtime advisories in 51 packages | `docs/dependency_audit_runtime.json` |

**This is not a penetration test.** It is unauthenticated, automated, and
surface-level. It did not attempt authentication bypass, tenant isolation
attacks, upload parser abuse, SSRF, race conditions, or business-logic flaws, and
it did not use valid test accounts. Passing it does not satisfy any exit
criterion in section 8, and it must not be cited as third-party assurance.

What it does establish is narrower: the public surface has no scanner-level
failures, the codebase has no medium/high static-analysis findings, the image has
no critical or fixable findings, and those checks now run in CI so they cannot
regress silently. See `docs/SECURITY_AND_COMPLIANCE.md` for the full evidence.

## 10. Current status

| Item | Status |
|---|---|
| Vendor selected | No |
| Authorization signed | No |
| Test executed | No |
| Report received | No |
| Critical/high findings resolved | Not applicable yet |
| Retest completed | No |
| Internal automated assessment | Completed (not a substitute; section 9) |

**Blocked by:** no external tester has been engaged. The assistant cannot
commission or perform an independent test. This is an organizational action, not
a code change.

## 11. Interim position

Until the test is complete:

- keep the service off the public internet;
- keep the demo on synthetic data;
- do not claim enterprise readiness or third-party assurance;
- treat the internal review in `docs/SECURITY_AND_COMPLIANCE.md` as a gap list,
  not as a substitute for independent testing.
