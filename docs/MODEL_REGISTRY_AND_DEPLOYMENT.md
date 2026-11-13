# Model Registry and Deployment Gate (Phase S3)

**Status:** implemented for the research prototype.
**Date:** 2026-11-09.

This document describes how model versions, artifacts, feature schemas,
threshold policies, and calibration versions are pinned, verified, promoted,
rolled back, and checked at deployment time.

## 1. The problem this solves

Before S3, the serving process loaded `models/model_bundle.pkl` if it existed.
The artifact hash was only checked when `MODEL_SHA256` happened to be set, and a
stored prediction did not record which artifact, feature schema, threshold, or
calibration produced it. That makes a prediction impossible to reproduce and a
silent artifact swap impossible to detect.

S3 adds:

- a registry that records every model version and its hashes;
- a startup gate that refuses a serving artifact that does not match the
  approved active version;
- provenance columns on every stored prediction;
- a tested promotion and rollback path;
- optional HMAC signing of registry entries.

## 2. What is pinned

For each registered version, `models/registry/registry.json` records:

| Field | Purpose |
|---|---|
| `model_id`, `version`, `role`, `status` | Identity and lifecycle state |
| `artifact_path`, `artifact_sha256`, `artifact_size` | Exact artifact bytes |
| `feature_schema_version`, `feature_schema_sha256`, `feature_count`, `features` | Exact feature names and order |
| `threshold_policy` | Policy name, threshold, max FPR, score definition, decision rule |
| `calibration_version`, `calibration_method`, `calibration_artifact`, `calibration_artifact_sha256` | Calibration linkage |
| `dataset_sha256`, `training_config` | Reproduction inputs |
| `created_at`, `created_by`, `approved_at`, `approved_by` | Accountability |
| `signature`, `verification` | HMAC-SHA256 or hash-only status |
| `history` | Register/approve/activate/rollback events |

The feature schema hash is `SHA-256` over the canonical JSON list of feature
names. The current schema is
`cic-ids-2017-80f-45cd75ce849b`
(`45cd75ce849b005c854ef8190a1cbe14d0d1a22daa6aa10e05e767ec6a757be6`).

## 3. Current registry contents

| Model ID | Version | Role | Status | Artifact SHA-256 |
|---|---|---|---|---|
| `netshield-flow` | `serving-rf-day-based-seed42-v1` | serving | approved, active | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| `netshield-flow` | `serving-lr-day-based-seed42-v1` | serving | approved (history) | `f6d3a5c1e90008bf3ba8789591c46067d4b59f0523328f745aa536a8d0d2925d` |
| `netshield-rf-research` | `rf-day-based-seed42-v1` | research | approved | `fa4c78a38b9ae6e596df37708107a0c1c727b38a774243bbc24318860ae01350` |
| `netshield-rf-research` | `rf-day-based-seed43-v1` | research | approved | `25800da4d1cf3899babd3c65fe6b9dc1f5e6a2cac1e8cdce54fc9b9c9b8154ab` |
| `netshield-rf-research` | `rf-day-based-seed44-v1` | research | approved | `4246d17268a763ce37b21147a0436cc1801f9d7a1c4a476f0c1f1150d6909328` |
| `netshield-rf-research` | `rf-day-based-seed45-v1` | research | approved | `4cfe17e605d80e0d5ee6b1d7e9012a10509d344b6a409ff10f9406548c2c2cec` |
| `netshield-rf-research` | `rf-day-based-seed46-v1` | research | approved | `7c0fcb6c4af55647aaf82067a1caa87bf0db6a3f720d1c480dcba5eaf859dee0` |

The active serving artifact is the evaluated seed 42 Random Forest
(`BENIGN`, `FTP-Patator`, `SSH-Patator`) with
`attack_threshold = 0.002515048908954043` and
`threshold_selection_max_fpr = 0.01`. Its SHA-256 equals the evaluated seed 42
manifest. The serving entry records `calibration_version: "uncalibrated"`
because the available isotonic artifact has held-out ECE ≈0.208 and fails the
0.05 gate.

The research entries are the five frozen Random Forest seeds used by D3/D4/D5.
Each records its own threshold and links to
`models/calibration_rf_day_based_seed{42..46}.json`. Seed 42 is now the same
bytes that are served; the other seeds remain research reproductions.

## 4. Serving path

At startup, `app.py`:

1. resolves the active registry artifact; an explicit `MODEL_ARTIFACT_PATH`
   still overrides it;
2. reads the active registry entry from `MODEL_REGISTRY_PATH` (default
   `models/registry/registry.json`);
3. verifies the artifact hash, size, feature schema, threshold, calibration
   artifact hash, and signature;
4. aborts if `REQUIRE_APPROVED_MODEL` is true and any check fails.

`REQUIRE_APPROVED_MODEL` defaults to `true` in production and `false` in
development. In development, a failed check is recorded in
`_serving_artifact["registry_status"]` and the app continues so a research demo
can still run. That fallback is explicit and is visible in the research
provenance panel.

The live ingest path applies the recorded attack-score threshold
`1 - P(BENIGN) >= threshold`. It stores:

- `model_version`
- `artifact_sha256`
- `feature_schema_version`
- `threshold_policy`
- `threshold_value`
- `calibration_version`
- `decision_basis`
- `attack_score`
- `model_argmax_label`

The batch `/predict` path applies the same policy. The raw argmax label is
retained separately so the threshold decision never hides the multiclass
prediction. The console does not show a confidence percentage because the
serving artifact is uncalibrated.

## 5. Promotion

```bash
# Register a candidate. This does not approve or activate it.
# Version name and threshold below are placeholders for the candidate bundle.
python -m training.model_registry register \
  --model-id netshield-flow \
  --version serving-rf-v2 \
  --artifact models/model_bundle_rf_day_based_seed42.pkl \
  --role serving \
  --threshold 0.002515048908954043 \
  --max-fpr 0.01 \
  --calibration-version uncalibrated \
  --created-by "model-owner"

# Verify before approval.
python -m training.model_registry verify \
  --model-id netshield-flow --version serving-rf-v2

# Approve.
python -m training.model_registry approve \
  --model-id netshield-flow --version serving-rf-v2 \
  --approver "security-reviewer"

# Activate.
python -m training.model_registry activate \
  --model-id netshield-flow --version serving-rf-v2 \
  --actor "deployer"
```

A candidate cannot be activated. Activation re-verifies the entry. Every action
appends a history event.

## 6. Rollback

```bash
python -m training.model_registry rollback \
  --model-id netshield-flow \
  --to-version serving-rf-day-based-seed42-v1 \
  --actor "incident-commander"
```

Rollback requires the target to be approved and to pass verification. It records
the previous active version in the history. `tests/test_model_registry.py`
exercises register, approve, activate, rollback, tamper detection, schema
mismatch, and signature verification.

## 7. Deployment check

```bash
python scripts/deployment_check.py
python scripts/deployment_check.py --json
```

The check fails when:

- the registry has no active version;
- the active version is not approved;
- the serving artifact hash or size differs;
- the feature schema differs;
- the bundle's attack threshold differs from the approved policy;
- a calibration artifact is missing or its hash differs;
- a signed entry's HMAC does not verify;
- `MODEL_SHA256` is set and does not match.

Exit code is non-zero on failure, so it can gate CI and the container
entrypoint.

## 8. Signing

Set `MODEL_SIGNING_KEY` to sign entries with HMAC-SHA256. The signature covers
every entry field except `signature` and `verification`. A signed entry cannot
be verified without the key, and changing any field invalidates the signature.

This protects the registry document from accidental or unauthorized edits. It
does **not** provide hardware-backed signing, key rotation, or a managed
artifact store. A production design should use a KMS/HSM and an immutable
artifact repository.

## 9. Schema-mismatch refusal

A model trained on a different feature order or feature set is refused even if
its file hash matches a previously approved artifact, because the registry pins
both the schema hash and the full feature list. `deployment_check` recomputes the
schema from the artifact and compares it to the approved entry.

## 10. Reproduction

```bash
# Verify the active artifact against the approved registry entry.
python scripts/deployment_check.py

# Inspect the registry.
python -m training.model_registry --json status

# Run the registry and provenance tests.
pytest tests/test_model_registry.py -q
```

The registry is rebuilt from the frozen artifacts; it does not retrain anything.
Registration calls are documented in `models/registry/README.md`.

## 11. Limitations

- The registry is file-based. It has no database, locking, or concurrent-writer
  protection. Two simultaneous writers can overwrite each other.
- It stores absolute paths for locally registered test artifacts; production
  entries should use repository-relative paths.
- Pickle artifacts are executable content. Hash and signature verification
  prove integrity, not safety. Only load artifacts from a trusted source.
- The serving artifact is the evaluated seed 42 Random Forest with a known
  weak operating point. Registry integrity does not improve detection quality.
- Registry identity is enforced, but the detector still fails the FPR, alert
  rate, Bot recall, calibration, external, and pilot gates.
- There is no automated promotion pipeline; promotion is a documented CLI
  process.
- There is no immutable, external audit trail for registry history.
