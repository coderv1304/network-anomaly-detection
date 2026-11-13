# Model registry

`registry.json` is the version-pinning and verification record for every model
artifact this repository can serve or has evaluated. It is deliberately
file-based: it can be reviewed in a diff, signed, backed up, and checked in.

The registry is **not** a managed artifact store. Artifacts still live in
`models/`. The registry records what each artifact is, what it was trained on,
which threshold policy and calibration version apply, and whether it is
approved for use.

## Current contents

| Model ID | Version | Role | Status | Artifact |
|---|---|---|---|---|
| `netshield-flow` | `serving-lr-day-based-seed42-v1` | serving | approved, active | `models/model_bundle.pkl` |
| `netshield-rf-research` | `rf-day-based-seed42-v1` … `seed46-v1` | research | approved | `models/model_bundle_rf_day_based_seed{42..46}.pkl` |

The serving artifact is a three-class Logistic Regression (`BENIGN`,
`FTP-Patator`, `SSH-Patator`). It is **not** the evaluated Random Forest. The
five Random Forest versions are the evaluated research artifacts; they are
registered so their hashes, thresholds, and calibration artifacts are pinned,
but they are not served.

The serving entry records `calibration_version: "uncalibrated"`. The console
must not display a confidence percentage for serving predictions.

## Verify the deployed artifact

```bash
python scripts/deployment_check.py
python scripts/deployment_check.py --json
```

The check fails when:

- the registry has no active version;
- the active version is not approved;
- the serving artifact's SHA-256 differs from the approved hash;
- the artifact's feature schema differs from the approved schema;
- the artifact's recorded attack threshold differs from the approved policy;
- a signed entry's HMAC does not verify.

In production, `app.py` runs the same check at startup and aborts if it fails.

## Promotion and rollback

```bash
# 1. Register a candidate (does not approve or activate it)
python -m training.model_registry register \
  --model-id netshield-flow --version serving-lr-v2 \
  --artifact models/model_bundle.pkl --role serving \
  --threshold 0.13454342680553322 --max-fpr 0.01

# 2. Approve after review and a successful verification
python -m training.model_registry approve \
  --model-id netshield-flow --version serving-lr-v2 --approver "reviewer"

# 3. Activate
python -m training.model_registry activate \
  --model-id netshield-flow --version serving-lr-v2 --actor "deployer"

# 4. Roll back to a previously approved version
python -m training.model_registry rollback \
  --model-id netshield-flow --to-version serving-lr-day-based-seed42-v1 \
  --actor "incident-commander"
```

Every register, approve, activate, and rollback action appends a history event
with the actor, timestamp, and artifact hash.

## Signing

Set `MODEL_SIGNING_KEY` to sign entries with HMAC-SHA256. Without a key, entries
are hash-verified only and the registry says so. A signed entry cannot be
verified without the key, and a changed field invalidates the signature.

Signing is integrity protection for the registry document, not a substitute for
a managed KMS/HSM. The key must be supplied by the deployment environment and
must never be committed.

## Schema mismatch refusal

The registry pins both the feature-schema hash and the full feature list. A
model artifact whose feature schema differs from the approved entry is refused
even if its file hash is otherwise valid. This prevents a model trained on a
different column order or feature set from being served under an approved
version label.

## Reproduction

The registry is rebuilt from the frozen artifacts by re-running registration
with the same artifact paths. The current serving hash is:

```
f6d3a5c1e90008bf3ba8789591c46067d4b59f0523328f745aa536a8d0d2925d  models/model_bundle.pkl
```

See `docs/MODEL_REGISTRY_AND_DEPLOYMENT.md` for the full process, the RF hashes,
and the limitations of this registry.
