"""
Supervised Threat Detection Model Training with XGBoost.
Trained on cleaned CICIDS2017 flow data with stratified train/validation/test splits.
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from xgboost import XGBClassifier

from backend.app.ml.preprocessor import CICIDSPreprocessor, SELECTED_FEATURES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "cicids2017_sample.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_OUTPUT_PATH = os.path.join(MODELS_DIR, "xgboost_detector.joblib")
ENCODER_OUTPUT_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")
METADATA_OUTPUT_PATH = os.path.join(MODELS_DIR, "xgboost_metadata.json")


def train_xgboost():
    os.makedirs(MODELS_DIR, exist_ok=True)

    if not os.path.exists(DATA_PATH):
        print(f"Data file not found at {DATA_PATH}. Generating sample dataset...")
        from scripts.download_cicids2017 import generate_development_sample
        generate_development_sample()

    print(f"Loading dataset from: {DATA_PATH}")
    df = pd.read_csv(DATA_PATH)
    print(f"Initial raw data shape: {df.shape}")

    # Preprocessing
    X, y = CICIDSPreprocessor.extract_features_and_labels(df)
    print(f"Features matrix shape: {X.shape}, Target classes: {y.unique()}")

    # Encode labels
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    classes = list(label_encoder.classes_)
    print(f"Encoded classes ({len(classes)}): {classes}")

    # Train (70%) / Validation (15%) / Test (15%) Stratified Split
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y_encoded, test_size=0.30, random_state=42, stratify=y_encoded
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    print(f"Dataset split sizes: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")

    # Initialize and train XGBClassifier
    xgb = XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        objective="multi:softprob",
        random_state=42,
        eval_metric="mlogloss",
        n_jobs=-1
    )

    print("Training XGBoost Classifier...")
    xgb.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False
    )

    # Evaluation on Test Set
    y_pred = xgb.predict(X_test)
    y_proba = xgb.predict_proba(X_test)
    test_accuracy = float(accuracy_score(y_test, y_pred))
    report = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    conf_matrix = confusion_matrix(y_test, y_pred).tolist()

    print("\n" + "=" * 55)
    print(f"XGBOOST TEST SET EVALUATION ACCURACY: {test_accuracy * 100:.2f}%")
    print("=" * 55)
    print(classification_report(y_test, y_pred, target_names=classes))

    # Save artifacts
    joblib.dump(xgb, MODEL_OUTPUT_PATH)
    joblib.dump(label_encoder, ENCODER_OUTPUT_PATH)

    metadata = {
        "model_name": "XGBoost Intrusion Detection",
        "algorithm": "XGBClassifier",
        "features": SELECTED_FEATURES,
        "classes": classes,
        "accuracy": test_accuracy,
        "macro_avg_f1": float(report["macro avg"]["f1-score"]),
        "weighted_avg_f1": float(report["weighted avg"]["f1-score"]),
        "confusion_matrix": conf_matrix,
        "classification_report": report,
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "evaluation_type": "DEVELOPMENT_EVALUATION",
        "research_evaluation_note": "Development model evaluation. Research-grade evaluation on original CICIDS2017 data is pending."
    }

    with open(METADATA_OUTPUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"Model successfully saved to: {MODEL_OUTPUT_PATH}")
    print(f"Metadata saved to: {METADATA_OUTPUT_PATH}")
    return metadata


if __name__ == "__main__":
    train_xgboost()
