from flask import Flask, render_template, request, jsonify
import pandas as pd
import numpy as np
import joblib
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Load the trained model and preprocessors
model = joblib.load("models/random_forest.pkl")
scaler = joblib.load("models/scaler.pkl")
label_encoder = joblib.load("models/label_encoder.pkl")
feature_names = joblib.load("models/feature_names.pkl")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400

    # Save uploaded file
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    try:
        # Try multiple encodings — CIC-IDS-2017 CSVs are often latin1
        df = None
        for enc in ['utf-8', 'latin1', 'ISO-8859-1', 'cp1252']:
            try:
                df = pd.read_csv(filepath, low_memory=False, encoding=enc)
                break
            except UnicodeDecodeError:
                continue
        if df is None:
            return jsonify({'error': 'Could not decode the CSV file. Try saving it as UTF-8.'}), 400

        # Strip whitespace from column names (CIC-IDS-2017 has leading spaces)
        df.columns = df.columns.str.strip()

        # Replace only +Inf with a large finite value — KEEP negative values intact!
        # Negative values like -1 in Init_Win_bytes_forward are valid sentinel values
        # that the model was trained on. Clipping them to 0 destroys attack signatures.
        df.replace([np.inf], 999999, inplace=True)
        df.replace([-np.inf], -999999, inplace=True)

        # Fill NaN with column median (keeps all rows — attack rows often have NaN)
        df.fillna(df.median(numeric_only=True), inplace=True)

        if len(df) == 0:
            return jsonify({'error': 'No valid rows remaining after cleaning. Check the file format.'}), 400

        # Drop non-feature columns (stripped names match training)
        cols_to_drop = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp', 'Label']
        X = df.drop(columns=[c for c in cols_to_drop if c in df.columns])

        # Verify all required features are present
        missing = [f for f in feature_names if f not in X.columns]
        if missing:
            return jsonify({'error': f'Missing {len(missing)} required column(s): {missing[:5]}{"..." if len(missing) > 5 else ""}'}), 400

        # Reorder columns to match training order exactly
        X = X[feature_names]

        # Scale and predict
        X_scaled = scaler.transform(X)
        predictions = model.predict(X_scaled)
        labels = label_encoder.inverse_transform(predictions)

        # Debug: print distribution to console
        unique, counts = np.unique(labels, return_counts=True)
        print("\n[NetShield] Prediction summary:")
        for lbl, cnt in zip(unique, counts):
            print(f"  {lbl}: {cnt}")

        result = {
            'total': len(labels),
            'benign': int(np.sum(labels == 'BENIGN')),
            'attack': int(np.sum(labels != 'BENIGN')),
            'attack_types': dict(zip(unique.tolist(), counts.tolist()))
        }

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)