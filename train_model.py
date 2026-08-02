"""
train_model.py
Train a Random Forest classifier on the CIC‑IDS‑2017 dataset.
Supports multiple CSV files and memory‑efficient processing.
Handles non‑UTF‑8 encoding and column name inconsistencies.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib
import os
import glob

# -------------------------------
# CONFIGURATION - EDIT THESE PATHS
# -------------------------------
DATA_FOLDER = "data"                     # Folder where CSV files are stored
OUTPUT_DIR = "models"                    # Where to save model and preprocessors
TEST_SIZE = 0.2                          # Fraction of data for testing
RANDOM_STATE = 42
N_ESTIMATORS = 100                       # Number of trees in Random Forest

# Select which files to use (comment out any you don't want)
# For low memory, use only the subset below.
CSV_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

# Alternatively, use only a representative subset (uncomment below):
# CSV_FILES = [
#     "Monday-WorkingHours.pcap_ISCX.csv",
#     "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
#     "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
#     "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
# ]

# -------------------------------
# 1. Load and combine CSV files with memory optimization
# -------------------------------
def load_data(file_list, folder):
    """Load multiple CSV files with encoding fallback and memory reduction."""
    df_list = []
    total_rows = 0

    # Encodings to try (CIC‑IDS‑2017 files often use latin1)
    encodings = ['utf-8', 'latin1', 'ISO-8859-1', 'cp1252']

    for file in file_list:
        filepath = os.path.join(folder, file)
        if not os.path.exists(filepath):
            print(f"⚠️ Warning: {filepath} not found. Skipping.")
            continue

        print(f"📂 Loading {file} ...")

        # Try different encodings until one works
        df = None
        for enc in encodings:
            try:
                df = pd.read_csv(filepath, low_memory=False, encoding=enc)
                print(f"   → Success with encoding: {enc}")
                break
            except UnicodeDecodeError:
                continue
            except Exception as e:
                print(f"   → Error with {enc}: {e}")
                continue

        if df is None:
            print(f"❌ Failed to read {file} with any encoding. Skipping.")
            continue

        # Strip whitespace from column names (common issue in CIC‑IDS‑2017)
        df.columns = df.columns.str.strip()

        # Downcast numeric columns to save memory
        for col in df.select_dtypes(include=['float64']).columns:
            df[col] = pd.to_numeric(df[col], downcast='float')
        for col in df.select_dtypes(include=['int64']).columns:
            df[col] = pd.to_numeric(df[col], downcast='integer')

        # Drop rows where label is missing (label column is now 'Label' after stripping)
        if 'Label' not in df.columns:
            print(f"⚠️ 'Label' column not found in {file}. Available columns: {list(df.columns[:5])}...")
            continue
        df.dropna(subset=['Label'], inplace=True)

        total_rows += len(df)
        print(f"   → {len(df):,} rows loaded. Total so far: {total_rows:,} rows")
        df_list.append(df)

    if not df_list:
        raise FileNotFoundError("No CSV files could be loaded. Check DATA_FOLDER and file names.")

    combined_df = pd.concat(df_list, ignore_index=True)
    print(f"\n✅ Combined dataset shape: {combined_df.shape}")
    return combined_df

# -------------------------------
# 2. Clean and preprocess data
# -------------------------------
def clean_data(df):
    """Remove duplicates, infinite values, and NaNs."""
    initial_rows = len(df)

    # Remove duplicate rows
    df.drop_duplicates(inplace=True)
    print(f"🗑️ Dropped duplicates: {initial_rows - len(df):,} rows removed")

    # Replace infinity with NaN and drop
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before_nan = len(df)
    df.dropna(inplace=True)
    print(f"🧹 Dropped NaN/Inf: {before_nan - len(df):,} rows removed")

    print(f"📊 Final cleaned shape: {df.shape}")
    return df

# -------------------------------
# 3. Feature selection and scaling
# -------------------------------
def prepare_features(df):
    """Separate features and labels, encode labels, scale features."""
    # Columns to drop (non‑feature columns) – note stripped names
    columns_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
    # Keep only columns that exist
    drop_cols = [c for c in columns_to_drop if c in df.columns]
    X = df.drop(columns=drop_cols + ['Label'])
    y = df['Label']

    # Encode labels (BENIGN -> 0, attacks -> 1 for binary, or keep multiclass)
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # Save feature names for later use in prediction
    feature_names = X.columns.tolist()

    # Scale features (important for some models, though Random Forest doesn't require it,
    # we still scale for consistency and possible future model changes)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y_encoded, label_encoder, scaler, feature_names

# -------------------------------
# 4. Train model and save artifacts
# -------------------------------
def train_and_save():
    print("\n🚀 Starting model training pipeline...")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Load and clean data
    df = load_data(CSV_FILES, DATA_FOLDER)
    df = clean_data(df)

    # Prepare features
    X, y, label_encoder, scaler, feature_names = prepare_features(df)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n✂️ Train size: {X_train.shape[0]:,} | Test size: {X_test.shape[0]:,}")

    # Train Random Forest
    print(f"🌲 Training Random Forest with {N_ESTIMATORS} trees...")
    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        random_state=RANDOM_STATE,
        n_jobs=-1,            # Use all CPU cores
        verbose=1             # Show progress (optional)
    )
    model.fit(X_train, y_train)

    # Evaluate
    accuracy = model.score(X_test, y_test)
    print(f"\n🎯 Test Accuracy: {accuracy:.4f}")

    # Save all artifacts
    joblib.dump(model, os.path.join(OUTPUT_DIR, "random_forest.pkl"))
    joblib.dump(scaler, os.path.join(OUTPUT_DIR, "scaler.pkl"))
    joblib.dump(label_encoder, os.path.join(OUTPUT_DIR, "label_encoder.pkl"))
    joblib.dump(feature_names, os.path.join(OUTPUT_DIR, "feature_names.pkl"))

    print(f"\n💾 Model and preprocessors saved to '{OUTPUT_DIR}/'")
    print("✅ Training completed successfully!")

# -------------------------------
# 5. Main execution
# -------------------------------
if __name__ == "__main__":
    train_and_save()