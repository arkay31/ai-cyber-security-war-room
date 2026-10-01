"""
Unsupervised Anomaly Detection Model Training with Isolation Forest.

Methodology (Phase 15 ML Standard):
BENIGN TRAIN -> TRAIN
VALIDATION   -> THRESHOLD CALIBRATION
UNSEEN TEST  -> FINAL METRICS (Do not evaluate on training data)

Note: Research-grade evaluation on original multi-gigabyte CICIDS2017 dataset is pending.
This script operates on the development sample baseline.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score

from backend.app.ml.preprocessor import CICIDSPreprocessor, SELECTED_FEATURES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "cicids2017_sample.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_OUTPUT_PATH = os.path.join(MODELS_DIR, "isolation_forest.joblib")
METADATA_OUTPUT_PATH = os.path.join(MODELS_DIR, "anomaly_metadata.json")


def train_isolation_forest():
    os.makedirs(MODELS_DIR, exist_ok=True)

    if not os.path.exists(DATA_PATH):
        print(f"Data file not found at {DATA_PATH}. Generating sample dataset...")
        from scripts.download_cicids2017 import generate_development_sample
        generate_development_sample()

    print(f"Loading dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)

    X, y = CICIDSPreprocessor.extract_features_and_labels(df)
    is_anomaly_ground_truth = (y != "BENIGN").astype(int)

    # 1. Split entire dataset into Train/Val/Test splits (60% / 20% / 20%) stratified by label
    X_train_full, X_temp, y_train_full, y_temp = train_test_split(
        X, y, test_size=0.40, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    # 2. BENIGN TRAIN: Filter strictly benign samples from training split
    benign_train_mask = (y_train_full == "BENIGN")
    X_benign_train = X_train_full[benign_train_mask]

    print(f"Dataset Split Sizes:")
    print(f"  Total records: {len(X)}")
    print(f"  Benign Train set (Normal baseline): {len(X_benign_train)}")
    print(f"  Validation set: {len(X_val)}")
    print(f"  Unseen Test set: {len(X_test)}")

    # 3. TRAIN: Fit Isolation Forest strictly on Benign Train baseline
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.08,
        max_samples="auto",
        random_state=42,
        n_jobs=-1
    )

    print("\n[Step 1/3] Fitting Isolation Forest strictly on Benign Train baseline...")
    iso_forest.fit(X_benign_train)

    # 4. VALIDATION: Threshold calibration on validation set
    print("[Step 2/3] Calibrating dynamic threshold on Validation split...")
    raw_val_scores = iso_forest.decision_function(X_val)
    min_val = float(raw_val_scores.min())
    max_val = float(raw_val_scores.max())

    norm_val_scores = 1.0 - ((raw_val_scores - min_val) / (max_val - min_val + 1e-9))
    val_labels = (y_val != "BENIGN").astype(int)

    # Find optimal threshold that maximizes F1 on validation split
    candidate_thresholds = np.linspace(0.40, 0.75, 36)
    best_threshold = 0.55
    best_f1 = 0.0

    for th in candidate_thresholds:
        preds = (norm_val_scores >= th).astype(int)
        f1 = f1_score(val_labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = float(th)

    print(f"  Calibrated Decision Threshold: {best_threshold:.3f} (Val F1: {best_f1:.4f})")

    # 5. UNSEEN TEST: Final evaluation on completely held-out test data
    print("[Step 3/3] Evaluating on UNSEEN TEST split...")
    raw_test_scores = iso_forest.decision_function(X_test)
    norm_test_scores = 1.0 - ((raw_test_scores - min_val) / (max_val - min_val + 1e-9))
    test_labels = (y_test != "BENIGN").astype(int)
    test_preds = (norm_test_scores >= best_threshold).astype(int)

    test_precision = float(precision_score(test_labels, test_preds, zero_division=0))
    test_recall = float(recall_score(test_labels, test_preds, zero_division=0))
    test_f1 = float(f1_score(test_labels, test_preds, zero_division=0))
    anomaly_rate = float(np.mean(test_preds))

    print("\n" + "=" * 60)
    print("UNSEEN TEST EVALUATION RESULTS (ISOLATION FOREST)")
    print("=" * 60)
    print(f"Test Precision:     {test_precision * 100:.2f}%")
    print(f"Test Recall:        {test_recall * 100:.2f}%")
    print(f"Test F1-Score:      {test_f1 * 100:.2f}%")
    print(f"Test Anomaly Rate:  {anomaly_rate * 100:.2f}%")
    print("=" * 60)

    # Save model and calibration metadata
    joblib.dump(iso_forest, MODEL_OUTPUT_PATH)

    metadata = {
        "model_name": "Isolation Forest Anomaly Detector",
        "algorithm": "IsolationForest",
        "features": SELECTED_FEATURES,
        "n_estimators": 150,
        "contamination": 0.08,
        "splits": {
            "benign_train_samples": int(len(X_benign_train)),
            "validation_samples": int(len(X_val)),
            "unseen_test_samples": int(len(X_test)),
        },
        "calibration": {
            "min_score": min_val,
            "max_score": max_val,
            "threshold": round(best_threshold, 3),
        },
        "unseen_test_metrics": {
            "precision": round(test_precision, 4),
            "recall": round(test_recall, 4),
            "f1_score": round(test_f1, 4),
            "anomaly_rate": round(anomaly_rate, 4),
        },
        "methodology": "BENIGN TRAIN -> FIT, VALIDATION -> CALIBRATE THRESHOLD, UNSEEN TEST -> EVALUATE",
        "research_evaluation_note": "Development model evaluation. Research-grade evaluation on original CICIDS2017 data is pending."
    }

    with open(METADATA_OUTPUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to: {MODEL_OUTPUT_PATH}")
    print(f"Metadata saved to: {METADATA_OUTPUT_PATH}")
    return metadata


if __name__ == "__main__":
    train_isolation_forest()
