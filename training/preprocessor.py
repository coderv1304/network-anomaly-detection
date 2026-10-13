"""
training/preprocessor.py

Unified, leak-free preprocessing and pipeline factory shared by both
offline training and live/batch inference.

Guarantees:
1. Scaler, imputer, and feature transformations are fit strictly on training data.
2. Inference calls only transform(), never fit().
3. Excludes non-generalizable network identifiers (Flow ID, IPs, Timestamps).
4. Maintains deterministic feature ordering.
"""

import numpy as np
import pandas as pd
from typing import List, Tuple, Optional
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.impute import SimpleImputer

# Non-feature identifiers that cause data leakage / overfitting if left in features
IDENTIFIER_COLUMNS = [
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Timestamp",
    "SimillarHTTP",
    "Label"
]

class FlowSanitizer(BaseEstimator, TransformerMixin):
    """
    Cleans column names, handles non-finite values (Inf/-Inf -> NaN),
    and enforces deterministic feature ordering.
    """
    def __init__(self, expected_features: Optional[List[str]] = None):
        self.expected_features = expected_features

    def fit(self, X: pd.DataFrame, y=None):
        if not isinstance(X, pd.DataFrame):
            return self
        
        # Clean columns
        cols = [c.strip() for c in X.columns]
        feature_cols = [c for c in cols if c not in IDENTIFIER_COLUMNS]
        if self.expected_features is None:
            self.expected_features = feature_cols
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X)
        else:
            X = X.copy()

        # Normalize column whitespace
        X.columns = X.columns.str.strip()

        # Drop non-feature columns if present
        cols_to_drop = [c for c in IDENTIFIER_COLUMNS if c in X.columns]
        if cols_to_drop:
            X.drop(columns=cols_to_drop, inplace=True)

        # Reindex to expected features if known
        if self.expected_features:
            # Add missing columns filled with 0.0
            for col in self.expected_features:
                if col not in X.columns:
                    X[col] = 0.0
            # Keep only expected features in exact deterministic order
            X = X[self.expected_features]

        # Convert to float and replace infinite values with NaN
        X = X.astype(np.float64, errors="ignore")
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        return X

def build_leak_free_pipeline(
    classifier,
    scaler_type: str = "standard",
    expected_features: Optional[List[str]] = None
) -> Pipeline:
    """
    Construct an sklearn Pipeline with:
    1. FlowSanitizer: strips identifiers, replaces Inf with NaN
    2. SimpleImputer: fits median strictly on train split
    3. Scaler (StandardScaler or RobustScaler): fits strictly on train split
    4. Classifier: model step
    """
    scaler = RobustScaler() if scaler_type == "robust" else StandardScaler()

    steps = [
        ("sanitizer", FlowSanitizer(expected_features=expected_features)),
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", scaler),
        ("classifier", classifier)
    ]
    return Pipeline(steps)
