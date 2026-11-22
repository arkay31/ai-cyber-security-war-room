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
EVAL_DIR = os.path.join(MODELS_DIR, "evaluation")
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

    # Compute confusion matrix metrics
    from sklearn.metrics import confusion_matrix
    tn, fp, fn, tp = confusion_matrix(test_labels, test_preds).ravel()
    test_precision = float(precision_score(test_labels, test_preds, zero_division=0))
    test_recall = float(recall_score(test_labels, test_preds, zero_division=0))
    test_f1 = float(f1_score(test_labels, test_preds, zero_division=0))
    specificity = float(tn / (tn + fp)) if (tn + fp) > 0 else 0.0
    fpr = float(fp / (tn + fp)) if (tn + fp) > 0 else 0.0
    fnr = float(fn / (tp + fn)) if (tp + fn) > 0 else 0.0
    anomaly_rate = float(np.mean(test_preds))

    # Anomaly score distribution for benign vs anomalous test records
    benign_scores = norm_test_scores[test_labels == 0]
    attack_scores = norm_test_scores[test_labels == 1]

    score_distributions = {
        "benign_flows": {
            "mean": round(float(np.mean(benign_scores)), 4),
            "std": round(float(np.std(benign_scores)), 4),
            "median": round(float(np.median(benign_scores)), 4),
            "p90": round(float(np.percentile(benign_scores, 90)), 4),
            "min": round(float(np.min(benign_scores)), 4),
            "max": round(float(np.max(benign_scores)), 4),
        },
        "attack_flows": {
            "mean": round(float(np.mean(attack_scores)), 4),
            "std": round(float(np.std(attack_scores)), 4),
            "median": round(float(np.median(attack_scores)), 4),
            "p10": round(float(np.percentile(attack_scores, 10)), 4),
            "min": round(float(np.min(attack_scores)), 4),
            "max": round(float(np.max(attack_scores)), 4),
        }
    }

    # Compute Benign Feature Baselines (mean & std across benign training records)
    benign_baseline = {}
    for feat in SELECTED_FEATURES:
        col_vals = X_benign_train[feat]
        benign_baseline[feat] = {
            "mean": round(float(col_vals.mean()), 4),
            "std": round(float(max(col_vals.std(), 1e-6)), 4),
            "min": round(float(col_vals.min()), 4),
            "max": round(float(col_vals.max()), 4),
            "p50": round(float(col_vals.median()), 4),
        }

    print("\n" + "=" * 60)
    print("UNSEEN TEST EVALUATION RESULTS (ISOLATION FOREST)")
    print("=" * 60)
    print(f"Test Precision:       {test_precision * 100:.2f}%")
    print(f"Test Recall:          {test_recall * 100:.2f}%")
    print(f"Test Specificity:     {specificity * 100:.2f}%")
    print(f"Test F1-Score:        {test_f1 * 100:.2f}%")
    print(f"False Positive Rate:  {fpr * 100:.2f}% (FP={fp}, TN={tn})")
    print(f"False Negative Rate:  {fnr * 100:.2f}% (FN={fn}, TP={tp})")
    print("=" * 60)

    # Save model and calibration metadata
    os.makedirs(EVAL_DIR, exist_ok=True)
    joblib.dump(iso_forest, MODEL_OUTPUT_PATH)

    eval_data = {
        "model_name": "Isolation Forest Anomaly Detector",
        "algorithm": "IsolationForest",
        "hyperparameters": {
            "n_estimators": 150,
            "contamination": 0.08,
            "max_samples": "auto"
        },
        "dataset_split": {
            "benign_train_samples": int(len(X_benign_train)),
            "validation_samples": int(len(X_val)),
            "unseen_test_samples": int(len(X_test)),
            "feature_count": len(SELECTED_FEATURES),
        },
        "calibration": {
            "min_score": round(min_val, 5),
            "max_score": round(max_val, 5),
            "decision_threshold": round(best_threshold, 3),
        },
        "metrics": {
            "precision": round(test_precision, 4),
            "recall": round(test_recall, 4),
            "f1_score": round(test_f1, 4),
            "specificity": round(specificity, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "true_positives": int(tp),
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn)
        },
        "score_distributions": score_distributions,
        "methodology": "Trained strictly on benign traffic; calibrated on validation split; evaluated on held-out test split.",
        "production_benchmark_distinction": (
            "These metrics reflect unsupervised anomaly separation on the CICIDS2017 flow sample. "
            "In production SOC deployment, benign traffic drifts over time (e.g. software updates, seasonal user shifts), "
            "requiring periodic threshold re-calibration and continuous baseline adaptation."
        )
    }

    with open(os.path.join(EVAL_DIR, "anomaly_evaluation.json"), "w") as f:
        json.dump(eval_data, f, indent=2)

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
            "specificity": round(specificity, 4),
            "fpr": round(fpr, 4),
            "fnr": round(fnr, 4),
            "anomaly_rate": round(anomaly_rate, 4),
        },
        "benign_feature_baseline": benign_baseline,
        "methodology": "BENIGN TRAIN -> FIT, VALIDATION -> CALIBRATE THRESHOLD, UNSEEN TEST -> EVALUATE",
        "production_benchmark_distinction": eval_data["production_benchmark_distinction"]
    }

    with open(METADATA_OUTPUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model saved to: {MODEL_OUTPUT_PATH}")
    print(f"Evaluation report saved to: {os.path.join(EVAL_DIR, 'anomaly_evaluation.json')}")
    print(f"Metadata saved to: {METADATA_OUTPUT_PATH}")
    return metadata


if __name__ == "__main__":
    train_isolation_forest()
