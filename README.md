# 🚨 Network Anomaly Detection

A machine learning–based web application for detecting anomalous network traffic using the **CIC-IDS-2017** dataset and a **Random Forest classifier**.

The project provides a complete workflow from model training to inference through a Flask web application. Users can upload network-flow CSV files and receive a summary of benign and attack traffic detected by the trained model.

> **Current scope:** This repository contains a Python/Flask machine-learning application for batch CSV-based network traffic analysis. It is not a live packet-capture or real-time network monitoring system.

---

## 📌 Overview

Network traffic can contain patterns associated with malicious or abnormal activity such as:

* DDoS
* DoS
* Port Scanning
* Web Attacks
* FTP Patator
* Other attack traffic represented in the training data

This project uses supervised machine learning to classify network-flow records based on the patterns learned from the **CIC-IDS-2017** dataset.

The trained model is exposed through a Flask application that allows a user to upload a CSV file and obtain prediction results.

---

## ✨ Features

* 🤖 Random Forest–based network traffic classification
* 📂 CSV file upload through a Flask web application
* 🔍 Automatic input-data cleaning
* 🧹 Whitespace normalization for CSV column names
* 🔢 Handling of missing numerical values
* ♾️ Handling of infinite numerical values
* 🔄 Feature-column ordering based on the training configuration
* 🧠 Reuse of the trained scaler and label encoder
* 📊 Prediction summary for uploaded traffic
* 🚨 Separation of benign and attack traffic
* 📋 Breakdown of detected traffic by predicted class
* 🌐 Web interface with dashboard and upload pages
* 📦 Pre-trained model artifacts included in the repository

---

## 🛠️ Tech Stack

| Category          | Technology               |
| ----------------- | ------------------------ |
| Language          | Python 3.x               |
| Web Framework     | Flask                    |
| Data Processing   | Pandas, NumPy            |
| Machine Learning  | Scikit-learn             |
| Model             | Random Forest Classifier |
| Model Persistence | Joblib                   |
| Frontend          | HTML, CSS, JavaScript    |
| Dataset           | CIC-IDS-2017             |
| Server            | Gunicorn                 |
| Version Control   | Git / GitHub             |

The repository currently pins Flask, Pandas, NumPy, Scikit-learn, and Joblib versions in `requirements.txt` and includes Gunicorn for application serving.

---

# 🧠 How It Works

The application follows this general workflow:

```text
                  Network Traffic CSV
                          │
                          ▼
                 ┌─────────────────┐
                 │   CSV Upload    │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Data Cleaning   │
                 │                 │
                 │ • Column names  │
                 │ • NaN handling  │
                 │ • Inf handling  │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Feature         │
                 │ Selection       │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ StandardScaler  │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Random Forest   │
                 │ Classifier      │
                 └────────┬────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │ Label Decoder   │
                 └────────┬────────┘
                          │
                          ▼
              ┌─────────────────────────┐
              │ Prediction Summary      │
              │                         │
              │ • Total records         │
              │ • Benign records        │
              │ • Attack records        │
              │ • Attack-type counts    │
              └─────────────────────────┘
```

---

# 🏗️ Project Components

## 1. Model Training

`train_model.py` is responsible for training the machine-learning model.

The script:

1. Reads CIC-IDS-2017 CSV files.
2. Handles inconsistent CSV encodings and column names.
3. Combines the selected datasets.
4. Cleans the input data.
5. Encodes the target labels.
6. Splits the data into training and testing sets.
7. Standardizes the feature values.
8. Trains a Random Forest classifier.
9. Evaluates the trained model.
10. Saves the trained model and preprocessing artifacts.

The training configuration includes a test split of `0.2`, a random state of `42`, and `100` Random Forest estimators.

---

## 2. Saved Model Artifacts

The trained artifacts are stored inside the `models/` directory:

```text
models/
├── feature_names.pkl
├── label_encoder.pkl
├── random_forest.pkl
└── scaler.pkl
```

These files are loaded by the Flask application when it starts.

### Artifact Purpose

| File                | Purpose                                           |
| ------------------- | ------------------------------------------------- |
| `random_forest.pkl` | Trained Random Forest classifier                  |
| `scaler.pkl`        | Feature scaling used before prediction            |
| `label_encoder.pkl` | Converts encoded predictions back to class labels |
| `feature_names.pkl` | Stores the feature order expected by the model    |

---

# 🌐 Flask Application

The main application is implemented in `app.py`.

The Flask server:

* Loads the trained model and preprocessing artifacts.
* Provides the main web page.
* Provides a dashboard page.
* Accepts uploaded CSV files.
* Validates the uploaded file.
* Cleans and preprocesses the network-flow data.
* Runs the trained model.
* Returns prediction statistics as JSON.

The application also limits uploaded files to **16 MB** and uses `secure_filename()` when saving uploaded files.

---

## 🔌 Application Routes

| Route        | Method | Purpose                             |
| ------------ | ------ | ----------------------------------- |
| `/`          | GET    | Main application page               |
| `/dashboard` | GET    | Dashboard page                      |
| `/predict`   | POST   | Upload CSV and generate predictions |

The `/predict` endpoint expects a file upload and returns a JSON prediction summary.

Example response structure:

```json
{
  "total": 1000,
  "benign": 750,
  "attack": 250,
  "attack_types": {
    "BENIGN": 750,
    "DDoS": 150,
    "PortScan": 100
  }
}
```

---

# 🧹 Input Data Processing

Before prediction, the application performs several preprocessing steps.

### Column cleanup

Whitespace is removed from CSV column names to handle datasets where columns contain leading or trailing spaces.

### Infinite values

Positive and negative infinite values are replaced with large finite values.

### Missing values

Missing numerical values are filled using the median of the corresponding numerical column.

### Non-feature columns

The following columns are excluded when present:

```text
Flow ID
Source IP
Destination IP
Timestamp
Label
```

### Feature validation

The application checks whether the uploaded dataset contains all features expected by the trained model.

It then reorders the feature columns to match the exact order used during training before applying the saved scaler and model.

---

# 🧪 Test Dataset Generation

`create_and_test.py` is used to create a smaller test dataset from selected CIC-IDS-2017 traffic categories.

It samples traffic including:

* BENIGN
* DDoS
* PortScan
* Web Attacks
* DoS Hulk
* FTP Patator

The resulting data is shuffled and written to:

```text
test_dataset.csv
```

This provides a smaller dataset for testing the prediction application without processing the complete dataset.

---

# 📁 Repository Structure

The repository currently follows this structure:

```text
network-anomaly-detection/
│
├── models/
│   ├── feature_names.pkl
│   ├── label_encoder.pkl
│   ├── random_forest.pkl
│   └── scaler.pkl
│
├── static/
│   ├── css/
│   └── js/
│
├── templates/
│   ├── dashboard.html
│   └── index.html
│
├── app.py
├── create_and_test.py
├── network_test_dataset.csv
├── test_dataset.csv
├── train_model.py
├── your_script.py
├── requirements.txt
├── Procfile
├── usecase.puml
├── .gitignore
├── LICENSE
└── README.md
```

The repository also contains the project datasets and generated model artifacts.

---

# 🚀 Getting Started

## 1. Clone the Repository

```bash
git clone https://github.com/coderv1304/network-anomaly-detection.git

cd network-anomaly-detection
```

---

## 2. Create a Virtual Environment

### Windows

```bash
python -m venv venv

venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

The current dependency file includes:

```text
Flask==2.3.2
pandas==2.2.3
numpy==2.1.3
scikit-learn==1.5.2
joblib==1.4.2
gunicorn
```

---

# ▶️ Run the Application

Start the Flask application with:

```bash
python app.py
```

The application runs on:

```text
http://localhost:5000
```

The Flask application is configured to listen on `0.0.0.0` and uses the `PORT` environment variable when available.

---

# 📤 Making Predictions

1. Start the Flask application.
2. Open the application in your browser.
3. Navigate to the prediction/upload interface.
4. Select a compatible network-flow CSV file.
5. Upload the file.
6. The application preprocesses the records.
7. The trained Random Forest model generates predictions.
8. The application returns a prediction summary.

The uploaded CSV should contain the features expected by the trained model.

---

# 📊 Output

The prediction endpoint reports:

* Total number of processed records
* Number of benign records
* Number of attack records
* Count of each predicted traffic class

For example:

```text
Total Records : 1000
Benign        : 750
Attack        : 250

Attack Types:
    BENIGN     : 750
    DDoS       : 150
    PortScan   : 100
```

---

# 📚 Dataset

This project uses the **CIC-IDS-2017** network intrusion detection dataset.

The training script is configured to work with multiple CIC-IDS-2017 CSV files, including traffic associated with:

* Monday working hours
* Tuesday working hours
* Wednesday working hours
* Thursday Web Attacks
* Thursday Infiltration
* Friday working hours
* Friday PortScan
* Friday DDoS

The dataset itself is not reproduced in this repository's documentation. The training script expects the relevant CSV files to be available in the configured data directory.

---

# ⚠️ Current Limitations

This project currently has several limitations worth being explicit about:

* Predictions are performed on uploaded CSV files rather than directly from live network packets.
* The application does not currently use a database.
* There is no authentication or authorization layer.
* There is no automated CI/CD pipeline.
* There is no container configuration in the current repository.
* There is no cloud infrastructure configuration.
* Model retraining is currently a manual process.
* Model monitoring and drift detection are not implemented.
* The application is primarily designed for batch network-flow analysis.

These are potential areas for future development rather than features currently implemented in the repository.

---

# 🔮 Future Improvements

Possible future improvements include:

* [ ] Live packet capture and analysis
* [ ] REST API improvements
* [ ] Database integration
* [ ] Docker containerization
* [ ] Automated testing
* [ ] GitHub Actions CI/CD
* [ ] AWS deployment
* [ ] Model versioning
* [ ] Model monitoring
* [ ] Real-time alerting
* [ ] Authentication and authorization
* [ ] Improved dashboard visualizations
* [ ] Automated model retraining
* [ ] Network traffic streaming

---

# 📄 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

## 👤 Author

**coderv1304**

GitHub: [@coderv1304](https://github.com/coderv1304)
