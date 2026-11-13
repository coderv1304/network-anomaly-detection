# Model Artifacts Directory

This directory stores trained scikit-learn models and preprocessing artifacts:

| File | Size | Purpose |
| --- | ---: | --- |
| `random_forest.pkl` | ~1.7 MB | Legacy multi-class Random Forest used by the original batch path |
| `model_bundle_rf_day_based_seed42.pkl` | ~1.8 MB | Registry-active serving bundle (evaluated RF seed 42) |
| `scaler.pkl` | ~2.5 KB | `StandardScaler` feature transformer |
| `label_encoder.pkl` | ~0.6 KB | Multi-class target label encoder |
| `feature_names.pkl` | ~1.5 KB | Feature order specification |

The larger per-seed experiment bundles (`model_bundle_*_day_based_seed*.pkl`) and the
Tier A transfer bundle (`model_bundle_rf_tierA_group_seed42.pkl`, ~50 MB) are
regenerable local artifacts and are gitignored. Reproduce them with the commands
in [the model card](../docs/MODEL_CARD.md) and
[cross-dataset report](../docs/CROSS_DATASET.md).

For architecture details, training parameters, performance metrics, and known
dataset limitations, refer to [docs/MODEL_CARD.md](../docs/MODEL_CARD.md).
