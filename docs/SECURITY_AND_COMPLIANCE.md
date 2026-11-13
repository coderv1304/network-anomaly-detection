# Security and Compliance Evidence (Phase S4)

**Status:** internal scans and assessments completed against a built serving
image. One assurance item is blocked: the external penetration test.
**Enterprise readiness is not claimed.**
**Date:** 2026-11-10.
**Scope:** the Python application, `requirements-runtime.txt`,
`requirements.txt`, both Dockerfiles, the Go capture prototype, the built
serving image `netshield:ci`, the built capture image `netshield-capture:ci`,
and the repository working tree.

This document records what was actually run and what it found. It is not a
certification, an audit opinion, or a claim that the service is secure.

## 1. What was run

| Check | Tool | Artifact | Result |
|---|---|---|---|
| Runtime dependency audit | pip-audit | `docs/dependency_audit_runtime.json` | **0 advisories in 51 packages** |
| Development dependency audit | pip-audit | `docs/dependency_audit_requirements.json` | 1 advisory in 1 package (`scapy 2.5.0`, dev collector only, no fix) |
| Serving image build | Docker 29.9.2 | `docs/docker_build.log` | Built successfully; image `sha256:965f6046…e580` |
| Serving image scan | Trivy 0.76.1 | `docs/trivy_image.json` | **0 CRITICAL, 0 Python, 0 secrets, 0 misconfigurations**; 186 unfixed Debian OS advisories (47 HIGH, 74 MEDIUM, 65 LOW) |
| Actionable-findings gate | `scripts/security_gate.py` | `docs/security_gate.json` | **PASS** (no critical, no fixable, no secret, no failed misconfiguration) |
| Go dependency scan | Trivy 0.76.1 | `docs/trivy_go.json` | **0 advisories** after the `x/sys` update |
| Go tests | `go test ./...` | — | Pass |
| Static analysis | Bandit 1.7.9 | `docs/bandit_report.json` | 0 HIGH, 0 MEDIUM, 5 LOW (development scripts only) |
| Dynamic HTTP baseline | OWASP ZAP baseline | `docs/zap/zap_report.{json,md,html}` | **0 failures**, 4 warnings (informational; see section 6) |
| Secret scan | custom + Trivy | `docs/secret_scan.json` | 0 findings in 281 tracked and untracked non-ignored files |
| Model artifact gate | registry | registry report | Passed for the serving artifact |
| External penetration test | third party | — | **Blocked:** not commissioned |

The installed-environment audit is reported separately from the requirements
audit. The local environment contains training and documentation packages that
are not declared runtime dependencies, so its advisory count is not the product's
exposure. `requirements-runtime.txt` is the shipped surface.

## 2. Findings summary

Full structured tracker: `docs/SECURITY_FINDINGS.json`.

| Severity | Open | Accepted | Resolved | Blocked |
|---|---|---|---|---|
| Critical | 0 | 0 | 0 | 0 |
| High | 0 | 0 | 4 | 1 |
| Medium | 3 | 2 | 7 | 0 |
| Low | 0 | 2 | 3 | 0 |

Open medium findings are secret management, retention/deletion coverage, and
audit tamper-evidence. They are product and process gaps, not exploitable code
defects found by this assessment. The blocked high item is the external
penetration test.

### Resolved in this round

- `lightgbm` 4.5.0 → 4.7.0 (training only; not in the serving image).
- `python-socketio` → 5.16.2, `eventlet` → 0.40.3, `requests` → 2.33.0,
  `python-dotenv` → 1.2.2, `pytest` → 9.0.3, Flask 3.1.3 / Werkzeug ≥3.1.9.
- Runtime/development requirements split; pytest, ruff, bandit, lightgbm, and
  shap are no longer in the serving image.
- Serving image uses `scapy==2.7.0` and no longer installs `pyflowmeter`.
- The pip vendored `bom.cdx.json` was removed from the image. Scanners were
  reading pip's own BOM as installed packages and reporting CVEs for setuptools
  70.3.0 while the installed version is 84.2.1.
- `golang.org/x/sys` → v0.50.0; builder image → `golang:1.26-alpine`.
- The image was **broken**: `.dockerignore` excluded `training/`, but `app.py`
  imports `training.model_registry` and unpickles classes from
  `training.preprocessor`. The built image failed to boot. It now keeps exactly
  those two modules and boots with a read-only root filesystem.
- Compose hardened: read-only root, `cap_drop: ALL`, `no-new-privileges`,
  tmpfs `/tmp`, and named volumes for the only writable paths.
- Security headers added: CSP, COOP, COEP, and `Cache-Control: no-store` for
  non-static responses. Google Fonts was removed, so the UI no longer makes
  third-party requests.
- CI workflow added at `.github/workflows/security.yml`, backed by
  `scripts/security_gate.py` and its unit tests. The workflow also records the
  S8 release-gate verdict as a non-blocking artifact: until an external review
  and a real pilot exist, a FAIL/BLOCKED verdict is the expected result.

## 3. The Debian OS baseline (186 advisories)

The serving image is based on `python:3.11-slim`, currently Debian 13.7. Trivy
reports 186 OS advisories and **none has a fixed version in the archive**:

| Package family | Examples | HIGH count |
|---|---|---|
| util-linux | `bsdutils`, `mount`, `login`, `libblkid1`, `libmount1`, `libuuid1` | 36 |
| sqlite | `libsqlite3-0` | 3 |
| ncurses | `libncursesw6`, `libtinfo6`, `ncurses-bin` | 2 |
| systemd libraries | `libsystemd0`, `libudev1` | 2 |
| acl, perl-base | `libacl1`, `perl-base` | 2 |

Every package with an installed version is tracked by Debian, and `apt-get
upgrade` at build time installs every available fix. Replacing the base image
was measured, not assumed:

| Base image | OS advisories | Critical |
|---|---|---|
| `python:3.11-slim` (Debian 13.7, current) | 186 | 0 |
| `python:3.13-slim-trixie` | 197 | 0 |
| `gcr.io/distroless/python3-debian12:nonroot` | 330 | 2 |

Switching base images would make the count worse. Alpine was not adopted
because the numerical stack (`numpy`, `pandas`, `scikit-learn`) and
`psycopg[binary]` would need source or musl builds, which is a larger and
riskier change than the advisory reduction justifies today.

**Compensating controls:** the app runs as UID 999, Compose uses a read-only
root filesystem with `cap_drop: ALL` and `no-new-privileges`, the image installs
only runtime dependencies, the demo binds to loopback, and the CI gate fails on
any CRITICAL or fixable finding. Most of the flagged binaries (`mount`,
`login`, `nsenter`, ncurses tools, perl) are not invoked by the serving process.

**Refresh policy:** rebuild and rescan on every base-image digest change, at
least monthly, and before any pilot. A base-image change that introduces a
CRITICAL or a fixable HIGH blocks the build until reviewed.

## 4. Secrets

**Result:** no committed secret was found in tracked files or untracked
non-ignored files by the custom scan or by Trivy's secret scanner. `.env` is
gitignored and was not present; only `.env.example` and `.env.staging.example`
with placeholder values are tracked.

This does not prove the absence of secrets in git history, build artifacts,
shell history, CI configuration, or an operator's environment. Any credential
that has ever been committed must be rotated, not merely deleted.

### Secret management requirements

- Production secrets must come from a managed secret store or KMS/HSM, not from
  a committed file or an operator's shell.
- Required secrets: `SECRET_KEY`, `LIVE_CAPTURE_API_KEY`,
  `NETSHIELD_ADMIN_PASSWORD_HASH`, `NETSHIELD_PROXY_SHARED_SECRET`,
  `MODEL_SIGNING_KEY`, `NETSHIELD_BACKUP_KEY`, `OIDC_CLIENT_SECRET`, and
  optionally `ABUSEIPDB_API_KEY`.
- TOTP secrets are Fernet-encrypted at rest with a key derived from
  `SECRET_KEY`, and recovery codes are stored only as password hashes. Rotating
  `SECRET_KEY` without re-enrolling authenticators therefore locks those
  accounts out; login fails closed with a 503 rather than skipping MFA.
- Scope each secret to one environment and one purpose. Do not reuse the
  serving API key as a collector key or a signing key.
- Rotate on a schedule and on any suspected exposure. Document the rotation
  runbook and test it.
- Never log secret values. The structured logger must not include request
  headers or environment dumps.

## 5. Supply chain and model artifacts

- The registry (`models/registry/registry.json`) pins each model artifact's
  SHA-256, feature-schema hash, threshold policy, and calibration version.
- `scripts/deployment_check.py` fails when the serving artifact differs from
  the approved active artifact. `app.py` runs the same check at startup and
  aborts in production if it fails.
- Registry entries can be HMAC-signed with `MODEL_SIGNING_KEY`. Without a key
  they are hash-verified only, and the registry says so.
- The image contains no repository SBOM, audit JSON, tests, training data, or
  documentation except `docs/summary_metrics.json`, which the app reads at
  runtime.
- The registry is not a managed artifact store and does not provide
  hardware-backed signing, immutable audit, or key rotation.

## 6. Container and HTTP assessment

### Container

The serving image was scanned after the boot fix:

```
netshield:ci (debian 13.7)   os-pkgs      186
Node.js                      lang-pkgs      0
Python                       lang-pkgs      0
```

The gate result is `PASS`: no critical, no fixable, no secret, and no failed
misconfiguration. The 186 unfixed OS advisories are reported, not hidden.

The container was also started under the Compose hardening equivalent:

```
--read-only --tmpfs /tmp
-v instance:/app/instance -v uploads:/app/uploads
```

`/healthz`, `/readyz`, `/`, and `/research` all returned 200.

### OWASP ZAP baseline (internal, unauthenticated)

The scan targeted the running container through `host.docker.internal`. This is
not a penetration test. It is an automated crawl of the public surface.

| Result | Count |
|---|---|
| FAIL | 0 |
| WARN | 4 |
| PASS | 64 |

The warnings are: `style-src 'unsafe-inline'` in the CSP, "modern web
application" (informational fingerprinting), session-management response
identified (the session cookie), and storable-but-non-cacheable content. None
is a failure. The CSP warning is tracked as S4-F-022 and requires a UI refactor,
not a server change. Inline scripts are not allowed, and Jinja autoescaping is
enabled.

### Static analysis

Bandit reports 0 HIGH and 0 MEDIUM. The five LOW findings are in
`scripts/load_test.py` (demo randomness) and `scripts/secret_scan.py` (a
`subprocess` call with a fixed, developer-controlled command). They are not on
the serving path.

## 7. Privacy, retention, export, and deletion

The data-lifecycle review is in `docs/PRIVACY_AND_DATA_LIFECYCLE.md`. Summary:

- Flow metadata (IP addresses, ports, protocol, prediction) is confidential and
  can be personal data.
- Tenant retention is configurable (1–3650 days, default 30). `POST
  /api/tenant/purge` deletes expired flows and their reviews, and writes an
  audit event.
- Tenant deletion removes flows, reviews, review audit, users, tenant-scoped
  audit rows, and the tenant row. The default tenant cannot be deleted.
- **Not covered:** database backups, object-storage copies, application logs,
  and external enrichment caches. A deletion promise that ignores these is
  incomplete.
- CSV export is permissioned and audited, but it exports raw IP addresses and
  ports with no redaction or per-field policy. Treat exports as confidential.
- There is no self-service data-subject request workflow, no residency control,
  and no automated deletion verification.

## 8. External penetration test

**Status: blocked.** No independent penetration test has been commissioned or
performed. The assistant cannot commission, scope, or complete one. The plan and
rules of engagement are in `docs/PENETRATION_TEST_PLAN.md`.

Until a test is completed and critical/high findings are resolved or formally
accepted, the service must not be described as penetration-tested or
enterprise-ready.

## 9. What this evidence supports

Supported:

- The serving image builds, boots, and serves its health and UI routes under a
  read-only, non-root, capability-free configuration.
- The shipped runtime requirements have zero known advisories, and the image
  has zero Python findings and zero fixable findings.
- The image has no scanned secrets and no failed configuration checks.
- An automated HTTP baseline found no failures.
- Dependencies were upgraded and the full test suite passes.
- Local accounts support TOTP MFA with encrypted secrets and hashed single-use
  recovery codes; `oidc.py` implements authorization-code + PKCE with RS256
  ID-token verification. OIDC is tested against a fake provider only.
- The serving artifact is hash-pinned and gated by a registry check.
- Retention, export, and deletion behavior is documented against the actual
  endpoints.

Not supported:

- "Enterprise-ready", "SOC 2 ready", "ISO 27001 ready", "penetration-tested",
  "zero known vulnerabilities", or "secure by default".
- Any claim that the prototype is safe to expose to the public internet.
- Any claim that deleting a tenant removes every copy of its data.
- Any claim that an automated ZAP baseline is an external security review.

## 10. Remediation order

1. Commission the external penetration test and track remediation.
2. Move secrets to a managed store and document rotation.
3. Extend retention/deletion to backups and caches, and add deletion
   verification.
4. Make the audit log tamper-evident.
5. Remove inline styles and drop `'unsafe-inline'` from the CSP.
6. Keep the base image refreshed; re-scan and re-baseline the OS advisories.
7. Enable the CI workflow on the repository host so findings cannot regress.

## 11. Reproduction

```bash
python -m pip_audit -r requirements-runtime.txt --format json \
  --output docs/dependency_audit_runtime.json
python -m pip_audit -r requirements.txt --format json \
  --output docs/dependency_audit_requirements.json
bandit -r app.py live_capture.py capture_interfaces.py pcap_parser.py \
  feature_mapper.py training monitoring scripts -f json \
  -o docs/bandit_report.json -x "./venv,./tests"
docker build -f Dockerfile -t netshield:ci .
trivy image --format json --output docs/trivy_image.json \
  --scanners vuln,secret,misconfig netshield:ci
python scripts/security_gate.py --report docs/trivy_image.json \
  --json docs/security_gate.json
docker run --rm -v "$PWD/docs/zap:/zap/wrk:rw" zaproxy/zap-stable \
  zap-baseline.py -t http://host.docker.internal:5000 \
  -J zap_report.json -w zap_report.md -r zap_report.html
python scripts/secret_scan.py --json docs/secret_scan.json
python scripts/deployment_check.py
```

`pip-audit -r` may need a writable cache:

```bash
PIP_CACHE_DIR=/tmp/pip-cache python -m pip_audit -r requirements.txt ...
```
