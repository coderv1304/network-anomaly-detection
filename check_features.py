"""
check_features.py

Run this once (python check_features.py) to see the exact feature
names your trained model expects. Compare this list against
http://127.0.0.1:5000/api/unmapped-features to fix mismatches in
feature_mapper.py's FEATURE_NAME_OVERRIDES.
"""

import joblib

feature_names = joblib.load("models/feature_names.pkl")
print(f"Model expects {len(feature_names)} features:\n")
for i, name in enumerate(feature_names, 1):
    print(f"{i:3}. {name}")