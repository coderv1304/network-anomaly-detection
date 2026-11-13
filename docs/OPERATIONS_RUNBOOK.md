# Operations Runbook (Phase S5)

**Status:** documented for the research prototype and a single-host reference deployment. **Not a production operations manual.** Several production controls listed here do not exist yet; they are marked as gaps, not as done.
**Date:** 2026-11-10.
**Related:** [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md), [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md), [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md), [`SECURITY_AND_PRODUCT_GAPS.md`](SECURITY_AND_PRODUCT_GAPS.md), [`backup_restore_drill.json`](backup_restore_drill.json).

## 1. Honest status

| Question | Answer |
| --- | --- |
| Is there an operations runbook? | Yes, this document. |
| Is infrastructure codified (IaC)? | **No.** Only `docker-compose.yml`. There is no Terraform, Helm, Kustomize, or Kubernetes manifest. |
| Is there a migration framework? | **Yes.** Alembic baseline `f68710d807f3` with a startup revision guard; development still uses `create_all()` plus idempotent helpers. See §5. |
| Is backup/restore tested? | **Yes.** `scripts/backup_restore_drill.py` passed on 2026-11-10. See §6. |
| Is backup off-host and encrypted? | **Procedure tested, operation not proven.** `scripts/backup_encrypted.py` passed an AES-256-GCM drill with authenticated restore and an optional off-host-directory hash check. No operated off-host storage exists. |
| Are RPO/RTO defined and met? | **No.** The drill records single-host RPO/RTO observations; no site-declared objective is established. |
| Is there an incident-response plan? | Yes, [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md). It has not been exercised as a drill. |
| Does the service meet its SLOs? | **At 20 flows/s, yes** for ingest latency: latest p95 164.9 ms. Capacity above 20 flows/s was not re-measured and the pre-optimization sweep first hit backpressure at 50 flows/s. See [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md). |
| Is this production ready? | **No.** |

## 2. Environments

| Environment | Purpose | Database | WSGI | Status |
| --- | --- | --- | --- | --- |
| Local development | Research, tests, UI | SQLite `instance/network_anomaly.db` | Flask dev server | Supported |
| Reference single host (`docker-compose.yml`) | Demonstrate the container split, read-only rootfs, volumes | SQLite in a named volume | gunicorn in the serving image | Supported, single host only |
| Staging profile | Release rehearsal | PostgreSQL required | WSGI server | **Profile exists; no operated staging environment** |
| Production (target) | Managed, multi-tenant | Managed Postgres (`DATABASE_URL`) | Multi-worker gunicorn behind a proxy | **Not implemented** |

`NETSHIELD_ENV=staging` applies the same authentication, secure-cookie,
PostgreSQL, shared rate-limit, migration, and local-capture rules as production.
It is a configuration preflight, not a provisioned environment. See
[`STAGING_AND_MIGRATIONS.md`](STAGING_AND_MIGRATIONS.md).

The application refuses SQLite when `NETSHIELD_ENV` is `production` or
`staging`:

```python
if os.environ["DATABASE_URL"].lower().startswith("sqlite:"):
    raise RuntimeError("Production and staging require a managed database; SQLite is for local research only.")
```

That guard is real. The managed database, secret manager, TLS termination, real
IdP integration, operated staging environment, and external penetration test it
implies do **not** exist.

## 3. Configuration reference

All configuration is environment variables. `.env.example` is the source of truth.

| Variable | Required | Meaning | Notes |
| --- | --- | --- | --- |
| `NETSHIELD_ENV` | Yes | `development`, `staging`, or `production` | Staging and production enable auth, secure cookies, PostgreSQL, and the SQLite guard |
| `MIGRATIONS_REQUIRED` | Staging/production | Refuse startup unless the DB is at the Alembic head | Defaults true in staging and production |
| `SECRET_KEY` | Production | Flask session signing, MFA secret encryption | Stored as an env var; **no managed secret store** |
| `LIVE_CAPTURE_API_KEY` | If capture enabled | Service key for `/api/flows` | Env var |
| `NETSHIELD_ADMIN_PASSWORD_HASH` | Production | Bootstrap admin password hash | Env var |
| `DATABASE_URL` | Yes | `sqlite:///...` or Postgres URL | SQLite only outside production |
| `MODEL_ARTIFACT_PATH` | Optional | Override the registry-active serving bundle | Default resolves the active registry artifact |
| `MODEL_SHA256` | Production | Expected artifact hash | Enforced by the deployment gate |
| `MODEL_REGISTRY_PATH` | Yes | Registry JSON | Default `models/registry/registry.json` |
| `MODEL_SIGNING_KEY` | If signed | HMAC key for registry entries | Env var |
| `REQUIRE_APPROVED_MODEL` | Production | Refuse unapproved artifacts | Defaults true in production |
| `SOCKETIO_ALLOWED_ORIGINS` | Yes | CORS allow-list | Comma-separated |
| `RATELIMIT_STORAGE_URI` | Yes | Rate-limit backend | `memory://` is single-process only |
| `ENABLE_LOCAL_CAPTURE` | No | Start capture inside the app | Opt-in |
| `NETSHIELD_CAPTURE_INTERFACE` | No | `auto` / `all` / `loopback` / list | `auto` follows the default route |
| `METRICS_ENABLED` / `METRICS_PORT` | No | Prometheus endpoint | Binds `127.0.0.1` by default |
| `MAX_CONTENT_LENGTH` | No | Upload cap | Default 50 MiB |
| `OIDC_ENABLED` | No | Enable OIDC SSO routes | Disabled unless an issuer, client, and redirect URI are set |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` / `OIDC_REDIRECT_URI` | If OIDC enabled | Provider and client registration | HTTPS issuer/redirect required in staging and production |
| `OIDC_JIT_PROVISIONING` / `OIDC_LINK_LOCAL_ACCOUNTS` | No | Provision unknown users / link existing local accounts | Both default false; leave false unless the site accepts the trust change |
| `NETSHIELD_BACKUP_KEY` | For encrypted backup | Base64 32-byte AES-256-GCM key | Env var; key custody is not operated |
| `NETSHIELD_OFFSITE_BACKUP_DIR` | Optional | Off-host backup destination | Presence is not proof of durability |

**Gap:** there is no secret manager, no rotation procedure, and no sealed-secret mechanism. Secrets live in `.env` or the orchestrator's environment.

## 4. Build and release

### 4.1 Build the serving image

```bash
docker build -t netshield:local -f Dockerfile .
```

The image already contains the serving artifact. Rebuild after any change to `app.py`, `feature_mapper.py`, `pcap_parser.py`, the registry-active artifact under `models/`, `templates/`, or `static/`.

### 4.2 Pre-release checks (all must pass)

```bash
# Full test suite
venv/Scripts/python.exe -m pytest tests/ -q

# Secret scan (tracked plus untracked non-ignored files)
python scripts/secret_scan.py

# Deployment gate: artifact hash, schema, threshold, calibration
python scripts/deployment_check.py

# Security gate: image scan, Python deps, secrets, misconfig
python scripts/security_gate.py

# Staging/production preflight: environment, DB, revisions, artifact, backup key
NETSHIELD_ENV=staging python scripts/preflight.py
```

Record the serving artifact hash. The current approved hash is:

```
fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350
```

### 4.3 Release manifest

Every release records:

- image digest (not just tag);
- `MODEL_ARTIFACT_PATH` and artifact SHA-256;
- feature schema version;
- threshold policy and threshold value;
- calibration version;
- registry entry version and status.

A release that changes the model or threshold requires a new registry entry. See [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md).

### 4.4 Deploy (reference single host)

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:5000/healthz
curl -fsS http://127.0.0.1:5000/readyz
```

The compose file runs the container with:

- `read_only: true` and `tmpfs: /tmp`;
- `security_opt: no-new-privileges:true`;
- `cap_drop: ALL`;
- writable volumes only for `instance/` (SQLite) and `uploads/`.

## 5. Database schema and migrations

### 5.1 What happens at startup

In `development`, `app.py` runs inside `app.app_context()`:

1. `db.create_all()` — creates missing tables.
2. `_ensure_tenant_columns()` — adds `tenant_id` and its index to pre-existing `flow`/`flow_reviews`/`flow_review_audit`.
3. `_ensure_flow_provenance_columns()` — adds `model_version`, `artifact_sha256`, `feature_schema_version`, `threshold_policy`, `calibration_version`, `attack_score`, `model_argmax_label`, `decision_basis`, `threshold_value` to `flow`.
4. `_ensure_user_mfa_columns()` — adds the TOTP and recovery-code columns to `users`.
5. `_bootstrap_tenant_and_admin()` — creates/repairs the default tenant and admin, and backfills `tenant_id` on null rows.

In `staging` and `production` the application does **not** create tables at
import. A release runs `python -m alembic upgrade head` as a deploy step, then
`migrations_runtime.assert_database_current()` fails startup if the database is
unversioned, behind, or ahead of the code. This is the reviewed path.

A database created by `create_all()` before Alembic existed must be verified and
stamped once:

```bash
python -m alembic stamp head
```

### 5.2 Migration rules

| Rule | Reason |
| --- | --- |
| Back up before upgrading | Downgrades are not rehearsed |
| Run `alembic upgrade head` before starting a release | Staging and production fail closed otherwise |
| Additive changes only where possible | Safer rollback to the previous image |
| Test restore on a copy before production | Rehearses the only rollback path |
| Never edit `instance/` by hand while the app is running | SQLite locking |
| Postgres in production | SQLite cannot satisfy multi-writer or HA |

**Gap:** there is only a baseline revision. No production migration history
exists, and no upgrade has been rehearsed against a staging snapshot.

### 5.3 Inspect schema and counts

```bash
python - <<'PY'
import sqlite3
con = sqlite3.connect("instance/network_anomaly.db")
print(con.execute("PRAGMA integrity_check").fetchone()[0])
for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
    print(name, con.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0])
con.close()
PY
```

## 6. Backup and restore

### 6.1 Procedure (SQLite)

**Never copy a live SQLite file with `cp`.** Use the online backup API so the copy is consistent under WAL/locking:

```bash
python scripts/backup_restore_drill.py
```

The script:

1. reads the live database (read-only);
2. takes an online backup with `sqlite3.Connection.backup`;
3. records size, page count, table counts, a logical SHA-256 over ordered rows, and `PRAGMA integrity_check`;
4. damages a disposable copy by deleting all `flow` rows;
5. restores the backup **over** the damaged copy and verifies counts, logical hash, and integrity;
6. restores again to a brand-new file and verifies the same;
7. writes `docs/backup_restore_drill.json`.

### 6.2 Last drill result

| Check | Result |
| --- | --- |
| Backup counts match source | Pass |
| Backup integrity | `ok` |
| Damage actually removed flows | Pass |
| Restore counts match backup | Pass |
| Restore integrity | `ok` |
| Restore logical SHA-256 matches backup | Pass |
| Fresh restore counts match | Pass |
| Fresh restore integrity | `ok` |
| Fresh restore hash matches | Pass |
| **Overall** | **pass** |

Artifacts are written to the gitignored `docs/backup_restore_artifacts/` directory; rerun the drill to regenerate them. The drill ran in about 1.3 s on a ~21.6k-flow database.

### 6.3 What the encrypted drill does and does not prove

`scripts/backup_encrypted.py` adds AES-256-GCM encryption, authenticated
decryption, a SHA-256 comparison with the plaintext backup, `PRAGMA
integrity_check`, an optional off-host-directory copy with hash verification,
and recorded restore time and source age. Its result is in
[`encrypted_backup_drill.json`](encrypted_backup_drill.json). The drill passes.

It still does not prove:

- An operator stores the key separately and rotates it.
- The off-host target is durable, replicated, or geographically separate.
- A site-declared RPO or RTO is met.
- The drill covers Postgres (the production target).
- It tests restoring while the app is serving writes.

### 6.4 Production backup requirements (not implemented)

1. Encrypted, off-host object storage with lifecycle policy.
2. A scheduled job with alerting on failure.
3. A documented RPO (maximum acceptable data loss) and RTO (maximum acceptable downtime).
4. Restore into an isolated environment, not over production.
5. Retention and deletion that includes backups.
6. A quarterly restore drill with a signed record.

## 7. Disaster recovery drill

**What was actually done (2026-11-10):** a backup was taken, a copy was deliberately damaged by deleting all flow rows, and both an in-place restore and a fresh-file restore were verified by counts, logical SHA-256, and `PRAGMA integrity_check`. Result: **pass**. See §6.2.

**What this is:** a backup/restore rehearsal on one host with a small SQLite database.

**What this is not:** a disaster-recovery drill. A real DR drill requires losing the primary host and recovering on separate infrastructure, with measured RTO and data loss. That infrastructure does not exist here, so a full DR drill is **blocked**.

## 8. Health and readiness

| Endpoint | Type | Behaviour |
| --- | --- | --- |
| `GET /healthz` | Liveness | Returns `{"status":"ok"}`. Does **not** check the database. |
| `GET /readyz` | Readiness | Runs `SELECT 1`; returns 503 if the database fails; otherwise `{"status":"ready","ingest":{...}}` |

Operational rules:

- Use `/healthz` only to decide whether to restart the process.
- Use `/readyz` to decide whether to route traffic.
- Both endpoints bypass auth and cache (`Cache-Control: no-store`).
- The container has been verified to return 200 on `/`, `/research`, `/healthz`, and `/readyz` under a read-only rootfs.

## 9. Rollback

### 9.1 Model rollback

The registry records activation and rollback history. To roll back:

1. Identify the previously active version in `models/registry/registry.json`.
2. Point `MODEL_ARTIFACT_PATH` and `MODEL_SHA256` at that version's artifact.
3. Update the registry entry status so the deployment gate accepts it.
4. Restart and confirm `/readyz` and the artifact hash in `/api/model` (or the provenance columns on a new flow).

A tested promotion/rollback path exists in [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md). It has been exercised in tests, not in a live incident.

### 9.2 Application rollback

Roll back to the previous image digest:

```bash
docker compose down
# edit image digest in compose or re-tag the previous digest
docker compose up -d
```

**Caveat:** if the new version ran an additive schema migration, the old code still works because the changes are additive. If a future version ever makes a destructive change, rollback requires the backup, not just the old image.

### 9.3 Database rollback

There is no rehearsed down-migration. The only rollback is:

1. stop the service;
2. restore the last verified backup (§6);
3. start the previous application version;
4. confirm `/readyz` and row counts.

## 10. Routine operations checklist

### Daily

- [ ] `/healthz` and `/readyz` are 200.
- [ ] Ingest queue is not stuck; flow count is rising.
- [ ] Disk usage on the `instance` and `uploads` volumes is below 80%.
- [ ] Backup job ran and its artifact hash was recorded.
- [ ] Error rate and p95 latency reviewed against [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md).

### Weekly

- [ ] Restore the latest backup into a scratch directory and run `PRAGMA integrity_check`.
- [ ] Review audit events for unexpected role or tenant changes.
- [ ] Confirm the serving artifact hash still matches the registry.
- [ ] Review rejected ingest (401/413/429) for a real client problem.

### Per release

- [ ] All pre-release checks in §4.2 pass.
- [ ] Release manifest recorded.
- [ ] New image digest recorded.
- [ ] Rollback target identified before deploy.

### Quarterly

- [ ] Full restore drill with a signed record.
- [ ] Review incident-response contacts and severity table.
- [ ] Re-run image and dependency scans.

## 11. Known gaps (do not mark as done)

| Gap | Impact |
| --- | --- |
| No IaC (Terraform/Helm/K8s) | Environments are hand-built; no reproducible infrastructure |
| No operated staging environment | A staging profile and preflight exist, but no provisioned DNS/TLS/database/deployment history |
| No production migration history | Only the Alembic baseline exists; no rehearsed production upgrade |
| Backup operation not proven | Encrypted drill passes, but off-host durability and key custody are unproven |
| No off-host storage | No real DR capability |
| No site-measured RPO/RTO | Recovery expectations undefined |
| No managed secret store | Secrets in env vars; no rotation. Rotating `SECRET_KEY` also invalidates encrypted TOTP secrets |
| No real IdP integration | OIDC is tested only against a fake provider |
| Capacity above 20 flows/s unmeasured | The 20 flows/s p95 SLO now passes; higher-rate behavior is unknown |
| No external penetration test | Security assurance incomplete |
| No incident-response drill | IR plan is untested |

## 12. Related documents

- [`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md)
- [`STAGING_AND_MIGRATIONS.md`](STAGING_AND_MIGRATIONS.md)
- [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md)
- [`MODEL_REGISTRY_AND_DEPLOYMENT.md`](MODEL_REGISTRY_AND_DEPLOYMENT.md)
- [`SECURITY_AND_PRODUCT_GAPS.md`](SECURITY_AND_PRODUCT_GAPS.md)
- [`backup_restore_drill.json`](backup_restore_drill.json)
- [`LIVE_CAPTURE_OPERATIONS.md`](LIVE_CAPTURE_OPERATIONS.md)
