# Incident Response Runbook (Phase S5)

**Status:** documented, **not exercised as a drill**. The only rehearsed recovery procedure is the SQLite backup/restore drill in [`backup_restore_drill.json`](backup_restore_drill.json). Treat this document as a plan, not as proof that the team can execute it under pressure.
**Date:** 2026-11-10.
**Related:** [`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md), [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md), [`SECURITY_AND_COMPLIANCE.md`](SECURITY_AND_COMPLIANCE.md).

## 1. Scope and honest limits

| Question | Answer |
| --- | --- |
| Is there an incident-response plan? | Yes, this document. |
| Is it staffed? | **No.** Ownership is nominal; this is a single-maintainer research project. |
| Has it been drilled? | **No** incident drill. Only backup/restore was rehearsed. |
| Is there 24/7 paging? | **No.** No paging integration. |
| Is there automated failover? | **No.** |
| Is there a communications team or legal process? | **No.** |

If an incident affects real users or real data, the honest action is to **stop, preserve evidence, and escalate to the site owner** rather than improvise production promises this project cannot keep.

## 2. Severity levels

| Severity | Definition | Examples | Response target |
| --- | --- | --- | --- |
| **SEV-1** | Confirmed data breach, credential exposure, or complete loss of service with no workaround | Secret key leaked publicly; database destroyed with no backup; ransomware | Immediate; notify project owner; preserve evidence |
| **SEV-2** | Major function unavailable or data integrity at risk | `/readyz` failing; ingest fully down; corrupt database; wrong model serving | 30 min business hours |
| **SEV-3** | Degraded service or single component failure | Backpressure, ingest p95 breach, alert delivery failures, capture adapter down | 4 h |
| **SEV-4** | Minor or cosmetic | UI glitch, single failed upload, non-critical log error | Next business day |

## 3. Roles (nominal)

| Role | Responsibility |
| --- | --- |
| Incident commander | Declares severity, owns the timeline, decides stop/rollback |
| Service maintainer | Runs application and database playbooks |
| Data/model owner | Model rollback, label/feature regressions, artifact integrity |
| Site/security owner | Data-handling decisions, breach notification, external communication |

One person may hold several roles. Record who actually held each role.

## 4. Detection sources

- Prometheus alerts (see the table in [`SLO_AND_ONCALL.md`](SLO_AND_ONCALL.md)).
- `/readyz` failing.
- User report.
- Audit log anomaly (role change, tenant change, export).
- Security scan or dependency advisory.
- External notification (hosting provider, researcher, customer).

## 5. General process

1. **Declare.** Assign severity, incident commander, and start a timestamped log.
2. **Stabilise.** Stop the bleeding before diagnosing: pause ingest, roll back the model, or stop the service.
3. **Preserve.** Do not delete logs, database files, or container filesystems. Copy them aside.
4. **Diagnose.** Use `/readyz`, metrics, structured logs, and the runbook playbooks.
5. **Mitigate.** Prefer the smallest reversible change: rollback over hotfix.
6. **Verify.** Confirm `/healthz`, `/readyz`, row counts, and artifact hash after the change.
7. **Communicate.** State impact, workaround, and next update time. Do not speculate.
8. **Close.** Write a postmortem (see §7) and link every artifact.

## 6. Playbooks

### 6.1 Ingest unavailable / backpressure (SEV-2/3)

**Symptoms:** `NetShieldIngestUnavailable`, `NetShieldIngestBackpressure`, `NetShieldNotReady`; clients receive 503 with `Retry-After`.

1. `curl -fsS http://HOST:5000/healthz` and `/readyz`.
2. If `/readyz` fails, go to §6.2.
3. Check `netshield_ingest_inflight` and `netshield_ingest_queue_depth`. If in-flight is pinned at `INGEST_MAX_INFLIGHT`, the service is saturated.
4. Check `netshield_ingest_stage_seconds{stage="persist"}`. Rising persist p95 means database contention or disk.
5. Mitigate, in order of preference:
   - tell collectors to honour `Retry-After` and back off;
   - reduce ingest rate at the source;
   - raise `INGEST_MAX_INFLIGHT` **only** after confirming the database can absorb it;
   - restart the process if it is wedged.
6. Do **not** promise that raising the limit fixes a database bottleneck. It usually makes it worse.

### 6.2 Readiness / database failure (SEV-2)

**Symptoms:** `/readyz` returns 503 with `"reason":"database"`; `PRAGMA integrity_check` fails; disk full.

1. Check disk: `df -h` on the `instance` volume.
2. Check integrity:
   ```bash
   python - <<'PY'
   import sqlite3
   con = sqlite3.connect("instance/network_anomaly.db")
   print(con.execute("PRAGMA integrity_check").fetchone()[0])
   con.close()
   PY
   ```
3. If the file is merely locked or the disk is full, free space and restart.
4. If integrity fails:
   - stop the service;
   - copy the corrupt file aside for evidence;
   - restore the last verified backup (§6.3);
   - confirm counts and integrity;
   - restart and confirm `/readyz`.
5. Record the data loss window (time between last backup and failure). There is **no RPO**, so this must be stated, not estimated away.

### 6.3 Restore from backup (SEV-1/2)

1. Stop the service: `docker compose down`.
2. Preserve the current database file (copy, do not delete).
3. Run the drill script against a copy first to validate the chosen backup:
   ```bash
   python scripts/backup_restore_drill.py --source <backup-file> --output /tmp/verify.json
   ```
4. Restore the verified backup over the live path using the SQLite backup API (not `cp`), per [`OPERATIONS_RUNBOOK.md`](OPERATIONS_RUNBOOK.md) §6.
5. Start the service and confirm `/healthz`, `/readyz`, table counts, and a new flow's provenance columns.

### 6.4 Failed deployment / bad artifact (SEV-2)

**Symptoms:** startup aborts with a deployment-gate error; `/readyz` fails after deploy; attack rate changes abruptly with no traffic change.

1. Capture the container logs and the failing hash/schema/threshold message.
2. Roll back to the previous image digest (§9 of the runbook).
3. If the model is the problem, roll back the registry to the previous active version and restart.
4. Confirm the artifact hash in a new flow's provenance columns matches the intended release.
5. Do not edit the registry by hand in production without recording why.

### 6.5 Suspected model regression (SEV-2/3)

**Symptoms:** attack rate jumps or collapses; a single family floods alerts; predictions look implausible for known traffic.

1. Compare the served artifact hash with the registry's active hash.
2. Check whether the feature schema changed.
3. Inspect the threshold policy and calibration version in the provenance columns.
4. If the artifact is wrong, roll back per §6.4.
5. If the artifact is correct but behaviour is wrong, **do not retune the threshold during an incident**. Record the observation and open a model investigation. The pilot protocol forbids mid-flight threshold changes.
6. Preserve sample flows for analysis.

### 6.6 Secret exposure (SEV-1)

**Symptoms:** `SECRET_KEY`, `LIVE_CAPTURE_API_KEY`, `MODEL_SIGNING_KEY`, or admin credentials appear in logs, a repository, a screenshot, or a support bundle.

1. Treat all impacted credentials as compromised.
2. Rotate every exposed secret and the admin password hash.
3. Invalidate sessions by rotating `SECRET_KEY`.
4. Search logs and repositories for further exposure.
5. Record scope, rotation time, and any window of unauthorised use.
6. **Gap:** there is no secret manager or automated rotation; rotation is manual and must be documented each time.

### 6.7 Suspected data breach / unauthorised access (SEV-1)

1. Do not delete anything. Preserve the database, logs, container filesystem, and audit events.
2. Pause ingest if it helps preserve state.
3. Identify what was accessed: flows, uploads, audit logs, users, tenants.
4. Escalate to the site/security owner immediately. Follow the site's legal and notification obligations.
5. This project has **no** automated breach-detection, no tenant-level encryption, and no tamper-evident audit log. Say so.
6. Record the timeline and the evidence chain.

### 6.8 Capture failure (SEV-3)

**Symptoms:** `flows_ingested: 0`; capture state `error`; an adapter missing.

1. Check `python live_capture.py --list` and `/api/capture-status`.
2. Confirm Npcap/libpcap is installed and the process has capture privilege.
3. Confirm the selected interface exists and has an IP (`auto` follows the default route).
4. With `all`, one adapter may fail without stopping the others; check `interface_states`.
5. If only loopback was attempted, note that idle loopback may produce no completed flows in the window. That is not a detection result.
6. Restart capture; if it still fails, fall back to the upload path and record the gap.

### 6.9 Disk full (SEV-2/3)

1. Identify the volume: `instance` (SQLite), `uploads`, or `/tmp`.
2. Do not delete the database. Move uploads or rotate logs instead.
3. Purge expired data only through the documented retention endpoint, not by hand.
4. Restart if the app is wedged; verify `/readyz`.

## 7. Postmortem template

| Field | Value |
| --- | --- |
| Incident ID / date | `<...>` |
| Severity | `<...>` |
| Duration | `<start – end, UTC>` |
| Impact | `<users, flows, data>` |
| Detection | `<how and when>` |
| Root cause | `<technical, not "human error">` |
| Contributing factors | `<...>` |
| What worked | `<...>` |
| What failed | `<...>` |
| Data loss | `<confirmed / none / unknown>` |
| Recovery action | `<rollback / restore / hotfix>` |
| Follow-up actions | `<owner + due date>` |
| Was this a planned capability? | `<yes/no>` |

## 8. Evidence preservation

Preserve, do not overwrite:

- `instance/network_anomaly.db` (and any WAL/SHM files);
- the gitignored `docs/backup_restore_artifacts/` output from the relevant drill (regenerate it with the drill command);
- container logs and `docker inspect` output;
- audit events (`audit_events` table and `/api/audit` export);
- `models/registry/registry.json` and the served artifact;
- the release manifest and image digest.

## 9. Communications

Internal update cadence: SEV-1 every 30 min, SEV-2 hourly, SEV-3 daily.

External messages must state: what is affected, what is not, the current workaround, and the next update time. Do **not** claim a fix is deployed before `/readyz` and artifact checks pass.

## 10. What is not implemented (do not pretend otherwise)

| Gap | Consequence |
| --- | --- |
| No paging integration | Alerts may sit unseen |
| No 24/7 rota | Response is best-effort |
| No automated failover | Host loss is an outage |
| No incident drill | This plan is untested |
| No RPO/RTO | Data-loss expectations are undefined |
| No operated off-host backup | Host loss can lose both primary and backup |
| No tamper-evident audit | Post-incident attribution is weak |
| No secret manager | Rotation is manual |
| No tenant encryption | Breach blast radius is the whole database |
| No legal/notification process | Site owner must supply it |
