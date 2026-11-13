# Tenancy, Identity, and Access Control (Phase S1)

**Status:** foundation implemented and covered by isolation tests. This is **not** a claim of enterprise or multi-tenant SaaS readiness.
**Date:** 2026-11-08.

## What S1 adds

- A `tenants` table and a default tenant for pre-existing rows.
- A `users` table with local password hashes, roles, and auth source.
- `tenant_id` on `flow`, `flow_reviews`, and `flow_review_audit`.
- Tenant scoping in every flow, review, stats, console snapshot, threat-intel, audit, and user query.
- Roles: `viewer`, `analyst`, `admin`, `platform_admin`.
- Local password login, optional TOTP MFA, OIDC SSO, legacy administrator login, and trusted-proxy SSO.
- An append-only `audit_events` table with no update or delete route.
- Tenant retention settings, an explicit purge endpoint, and tenant deletion.
- Isolation tests proving one tenant cannot read or mutate another tenant's data.

## Schema

| Table | Tenant key | Notes |
| --- | --- | --- |
| `tenants` | `id` | Slug, name, active flag, retention days |
| `users` | `tenant_id` | Nullable only for platform admins |
| `flow` | `tenant_id` | Backfilled to the default tenant |
| `flow_reviews` | `tenant_id` | Must match the parent flow |
| `flow_review_audit` | `tenant_id` | Must match the parent flow |
| `audit_events` | `tenant_id` | Nullable for platform-level events |

The bootstrap helper adds `tenant_id` to existing SQLite/Postgres tables when it is missing, creates an index, and backfills null values to the default tenant. In staging and production the reviewed schema path is Alembic (baseline `f68710d807f3` with a startup revision guard); the additive helper remains only for development databases created before Alembic.

P3 adds nullable `flow.sensor_id` and `flow.interface` columns. They are collector-supplied, not derived from `tenant_id`, and are never backfilled with a fabricated sensor. `GET /api/flows`, `GET /api/console/snapshot`, and `GET /api/sensors/summary` all apply the tenant scope before the sensor filter or aggregation. A sensor with the same name in two tenants is therefore two separate series.

## Roles and permissions

| Permission | viewer | analyst | admin | platform_admin |
| --- | ---: | ---: | ---: | ---: |
| `flows:read` | Yes | Yes | Yes | Yes |
| `flows:review` | No | Yes | Yes | Yes |
| `flows:export` | No | Yes | Yes | Yes |
| `audit:read` | No | Yes | Yes | Yes |
| `users:manage` | No | No | Yes | Yes |
| `retention:manage` | No | No | Yes | Yes |
| `tenants:manage` | No | No | No | Yes |
| `platform:admin` | No | No | No | Yes |

The service key is **ingest-only**. It cannot read flows, reviews, audit events, or admin endpoints.

## Authentication modes

### Local password login

- `POST /login` with optional `email` and required `password`.
- Users are stored in the `users` table with `generate_password_hash`.
- New users are created by a tenant admin at `POST /api/tenant/users`.
- Minimum password length is 12 characters.
- Login is rate-limited to 5 attempts per minute per remote address.

### Legacy administrator login

- If `email` is blank, the application checks `NETSHIELD_ADMIN_PASSWORD_HASH`.
- The bootstrap admin account is created from `NETSHIELD_ADMIN_EMAIL` (default `admin@localhost`).
- This preserves existing production login behavior.

### Trusted-proxy SSO

Enable only behind a reverse proxy that strips client-supplied copies of the headers:

```text
NETSHIELD_TRUSTED_PROXY_SSO=true
NETSHIELD_PROXY_SHARED_SECRET=<strong random secret>
```

The proxy sends:

```text
X-NetShield-User: analyst@example.com
X-NetShield-Proxy-Secret: <shared secret>
```

The user must already exist and be active. There is no auto-provisioning. This is **not** OIDC or SAML; it is a trusted-header integration.

### OIDC SSO and TOTP MFA

OIDC is an authorization-code flow with PKCE, `state`, `nonce`, and RS256
ID-token verification against the provider JWKS. It is disabled unless
`OIDC_ENABLED=true` and an issuer, client id, and redirect URI are configured.
Unknown users are denied unless `OIDC_JIT_PROVISIONING=true`; existing local
accounts are not linked by email unless `OIDC_LINK_LOCAL_ACCOUNTS=true`. See
[staging and migrations](STAGING_AND_MIGRATIONS.md) for the full policy.

Local password accounts can enroll TOTP MFA at `/account`. Secrets are encrypted
at rest and recovery codes are stored only as hashes. This is account-level MFA,
not proof that every tenant has enrolled.

These controls are tested against a local fake provider. No real Okta, Entra,
Keycloak, or Auth0 tenant has been integrated, so OIDC is not an operated SSO
claim.

### Development mode

When `NETSHIELD_ENV` is not `production`, requests without a session use an explicit local administrative identity (`local-user`) in the default tenant. This keeps local development usable. Never expose development mode publicly.

## Tenant scoping

`tenant_scoped(model)` is the single helper used by flow, review, audit, and stats queries:

```python
tenant_scoped(Flow).filter(Flow.id == flow_id).first_or_404()
```

Rules:

- A normal user sees only rows where `tenant_id == current_tenant_id()`.
- A platform admin may pass `tenant_id` as a query parameter or JSON field to inspect a specific tenant.
- An invalid platform-admin override returns no rows, never all rows.
- Service-key ingest writes to `NETSHIELD_INGEST_TENANT` (default `default`).
- A missing tenant filter is a bug, not a fallback.

## Audit logging

`audit_events` records:

- `auth.login`, `auth.logout`
- `flows.ingest`, `flows.list`, `flows.read`, `flows.export`
- `flows.review`, `flows.review_audit_read`
- `audit.read`
- `users.list`, `users.create`, `users.update`
- `tenant.retention_update`, `tenant.retention_purge`
- `tenants.list`, `tenants.create`, `tenants.delete`

Each event stores tenant, actor, role, action, resource type and ID, outcome, bounded JSON detail, IP address, user agent, and timestamp.

There is no update or delete route for audit events. Tenant deletion and retention purge are the only operations that remove rows, and both write their own audit event. This is append-only at the application layer, not tamper-evident at the storage layer; there is no hash chain or WORM store.

## API summary

| Endpoint | Permission | Purpose |
| --- | --- | --- |
| `GET /api/flows` | `flows:read` | Tenant-scoped flow history |
| `GET /api/flows/export` | `flows:export` | Tenant-scoped CSV export; audited |
| `GET /api/me` | authenticated | Identity, role, tenant, permissions |
| `GET /api/tenants` | `tenants:manage` | List tenants |
| `POST /api/tenants` | `tenants:manage` | Create tenant |
| `DELETE /api/tenants/<id>` | `platform:admin` | Delete tenant with `{"confirm": "<slug>"}` |
| `GET /api/tenant` | `tenant:admin` | Tenant info and counts |
| `GET /api/tenant/retention` | `retention:manage` | Read retention days |
| `PUT /api/tenant/retention` | `retention:manage` | Set retention days |
| `POST /api/tenant/purge` | `retention:manage` | Delete flows older than retention |
| `GET /api/tenant/users` | `users:manage` | List tenant users |
| `POST /api/tenant/users` | `users:manage` | Create local user |
| `PATCH /api/tenant/users/<id>` | `users:manage` | Change role or active flag |
| `GET /api/audit` | `audit:read` | Tenant-scoped audit events |

## Retention and deletion

- `retention_days` is per tenant, default 30, range 1–3650.
- Purge computes `cutoff = now - retention_days`, deletes matching flows and their review rows, and writes `tenant.retention_purge`.
- Tenant deletion requires platform-admin permission and a slug confirmation.
- Tenant deletion removes flows, reviews, review audit, users, tenant-scoped audit rows, and the tenant row.
- The default tenant cannot be deleted.
- There is no scheduled purge worker in this phase; purge is operator-triggered.
- Backups and external copies are not covered by tenant deletion.

## Isolation tests

`tests/test_tenancy.py` covers:

1. Two tenants with one flow each; each user sees only its own flow.
2. Cross-tenant flow detail returns 404.
3. Cross-tenant review update returns 404 and does not mutate the other tenant's review.
4. Tenant-scoped stats and console snapshots do not leak counts.
5. Viewer cannot review; analyst can.
6. Admin can manage users and retention; analyst cannot.
7. Platform admin can list tenants; tenant admin cannot.
8. Retention purge removes old flows and their reviews only for the target tenant.
9. Tenant deletion removes tenant-owned rows and requires confirmation.
10. Audit events are tenant-scoped.
11. Viewer cannot export; analyst can, and the export is audited.
12. `/api/me` returns the correct role, tenant, and permissions.

Run:

```bash
pytest tests/test_tenancy.py -v
pytest tests/test_app_auth.py -v
pytest tests/test_mfa.py -v
pytest tests/test_oidc.py -v
```

## What S1 does not claim

- A real IdP integration, SAML, SCIM, password reset, or session revocation. OIDC and TOTP MFA are implemented but tested only against a fake provider.
- Penetration-tested isolation.
- Backup/restore tenant isolation.
- A signed model registry or rollback.
- SLOs, on-call, billing, or a design-partner pilot.
- Multi-tenant SaaS readiness.

Those are later phases. S1 removes the "no tenancy at all" blocker; it does not earn a 9/10 SaaS score.
