# Project Scope and Claim Boundaries

## Project

NetShield is an educational network-flow research prototype. It accepts flow CSVs and packet-capture files for batch analysis, applies a local scikit-learn classification artifact, and presents predictions for human review. It also includes an experimental local packet-capture path and a live console that polls stored flow records and capture status. These paths are not evidence of a validated operational network detection service.

## Research goal

Measure how flow-based classifiers behave when traffic changes over time or attack families are absent from model training. Evaluate the consequences for family-level detection, false-positive behavior, alert volume, and analyst review burden. The current research evidence is an initial failure analysis on CIC-IDS-2017, not a successful detector claim.

## Intended use

- Coursework, controlled lab demonstrations, and reproducible model evaluation.
- Offline analysis of authorized flow CSV, PCAP, and PCAPNG data using the repository's supported formats and feature mappings.
- Human review of model predictions and retrospective exploration of classifier behavior.

## Out of scope

- Production intrusion detection, network-wide coverage, or a multi-tenant SaaS service.
- Confirming an incident, identifying every attack family, or detecting arbitrary zero-day attacks.
- Automated blocking, firewall changes, cloud changes, or external SOAR delivery.
- Treating a classifier label, anomaly indicator, or public-IP reputation result as verified threat intelligence.
- Claims that experimental capture features are equivalent to the training feature pipeline.

## Evidence status

- The sample random-row benchmark is exploratory and is not evidence of future-network performance.
- The full CIC-IDS-2017 weekday split has been inspected and used for model comparisons. It is development evidence, not a blind final test for future experiments.
- The Monday/Tuesday train, Wednesday validation, Thursday/Friday test result is weak: multiclass macro-F1 was 0.0857, only three labels were present in the learned vocabulary, and seven test labels were unseen. The frozen binary threshold results also varied by seed and day.
- The separate binary attack experiment did not establish useful general open-set detection. Per-family results are in [the temporal failure report](TEMPORAL_HOLDOUT_RESULTS.md).
- Paired feature parity, a fresh confirmatory holdout, an independent dataset, a prospective analyst study, and multi-tenant isolation have not been demonstrated.

## Claim boundaries for the interface and reports

Use **prediction**, **predicted label**, **non-benign prediction**, **sample data**, and **optional IP reputation enrichment** where applicable. Avoid **confirmed threat**, **malicious host**, **physical origin**, **validated threat intelligence**, and **live sensor** unless supported by a separate verified source or integration. The console's polling indicator describes browser polling of stored records; it does not imply a deployed sensor fleet. Response controls are local previews or mock webhook acknowledgments and execute no containment or external delivery.

## Product maturity

The application has a useful research and demonstration workflow. S1 adds a tenancy/RBAC/audit foundation: tenant-scoped queries, local and trusted-proxy identities, roles, TOTP MFA for local accounts, an OIDC authorization-code client with PKCE, retention controls, and isolation tests. S2 adds SLO definitions, Prometheus metrics, JSON logs, rate limits, and bounded backpressure; the latest 20 flows/s run meets the ingest-latency SLO after batch inference and WAL tuning, but sustained and higher-rate behavior is unmeasured. S3 adds a signed, hash-verified model registry with promotion, tested rollback, provenance on every stored prediction, and a startup deployment gate. S4 adds dependency/filesystem scans, an SBOM, a secret scan, a built and scanned serving image, and a CI gate; the image has zero critical, zero Python, and zero fixable findings, but 186 unfixed Debian OS advisories remain accepted baseline risk and the external penetration test is blocked. S5 adds a `staging` profile, an Alembic baseline with a startup revision guard, and a preflight gate, but no operated staging environment or production migration history. It is still not production SaaS: a real IdP integration, a completed penetration test, sustained SLO evidence, a staffed on-call rota, billing, a managed artifact and secret store, operated off-host backup with measured RPO/RTO, and a design-partner pilot are absent. See [scope and claims](SCOPE_AND_CLAIMS.md), [product boundary and threat model](PRODUCT_BOUNDARY_AND_THREAT_MODEL.md), [tenancy and access control](TENANCY_AND_ACCESS_CONTROL.md), [staging and migrations](STAGING_AND_MIGRATIONS.md), [SLOs and on-call](SLO_AND_ONCALL.md), [model registry and deployment](MODEL_REGISTRY_AND_DEPLOYMENT.md), [security and compliance](SECURITY_AND_COMPLIANCE.md), and [security and product gaps](SECURITY_AND_PRODUCT_GAPS.md).
