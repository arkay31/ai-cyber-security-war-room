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
import shap

from backend.app.ml.preprocessor import CICIDSPreprocessor, SELECTED_FEATURES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE_DIR, "data", "raw", "cicids2017_sample.csv")
MODELS_DIR = os.path.join(BASE_DIR, "models")
EVAL_DIR = os.path.join(MODELS_DIR, "evaluation")
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
    os.makedirs(EVAL_DIR, exist_ok=True)
    joblib.dump(xgb, MODEL_OUTPUT_PATH)
    joblib.dump(label_encoder, ENCODER_OUTPUT_PATH)

    # 1. Feature Importances (Gini/Gain)
    xgb_importances = xgb.feature_importances_.tolist()
    feature_importance_list = [
        {"feature": feat, "importance": round(float(imp), 5)}
        for feat, imp in zip(SELECTED_FEATURES, xgb_importances)
    ]
    feature_importance_list.sort(key=lambda x: x["importance"], reverse=True)

    # 2. SHAP Global Attribution
    print("Computing SHAP explanations on test split...")
    try:
        explainer = shap.TreeExplainer(xgb)
        # Use first 300 test samples for fast, representative global SHAP summary
        eval_sample = X_test[:300]
        shap_vals = explainer.shap_values(eval_sample)
        # shap_vals shape: (samples, features, classes) or list of (samples, features)
        if isinstance(shap_vals, list):
            mean_abs_shap = np.mean([np.abs(sv).mean(axis=0) for sv in shap_vals], axis=0)
        else:
            mean_abs_shap = np.abs(shap_vals).mean(axis=(0, 2)) if shap_vals.ndim == 3 else np.abs(shap_vals).mean(axis=0)

        shap_importance = [
            {"feature": feat, "mean_abs_shap": round(float(score), 5)}
            for feat, score in zip(SELECTED_FEATURES, mean_abs_shap)
        ]
        shap_importance.sort(key=lambda x: x["mean_abs_shap"], reverse=True)
    except Exception as e:
        print(f"Warning: SHAP computation encountered: {e}")
        shap_importance = []

    # 3. Structured evaluation outputs
    eval_summary = {
        "model_name": "XGBoost Threat Classification Engine",
        "algorithm": "XGBClassifier",
        "hyperparameters": {
            "n_estimators": 120,
            "max_depth": 6,
            "learning_rate": 0.08,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
            "objective": "multi:softprob"
        },
        "dataset_split": {
            "total_samples": len(df),
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
            "feature_count": len(SELECTED_FEATURES),
            "classes": classes
        },
        "metrics": {
            "accuracy": round(test_accuracy, 4),
            "macro_precision": round(float(report["macro avg"]["precision"]), 4),
            "macro_recall": round(float(report["macro avg"]["recall"]), 4),
            "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
            "weighted_precision": round(float(report["weighted avg"]["precision"]), 4),
            "weighted_recall": round(float(report["weighted avg"]["recall"]), 4),
            "weighted_f1": round(float(report["weighted avg"]["f1-score"]), 4)
        },
        "per_class_metrics": {
            cls: {
                "precision": round(float(report[cls]["precision"]), 4),
                "recall": round(float(report[cls]["recall"]), 4),
                "f1_score": round(float(report[cls]["f1-score"]), 4),
                "support": int(report[cls]["support"])
            }
            for cls in classes
        },
        "production_benchmark_distinction": (
            "These metrics reflect performance on a stratified development sample derived from the CICIDS2017 schema. "
            "In production enterprise environments, real-world network traffic undergoes distribution drift, zero-day evasion, "
            "and encrypted payload obfuscation. Continuous monitoring and human-in-the-loop validation remain mandatory."
        )
    }

    conf_matrix_data = {
        "classes": classes,
        "matrix": conf_matrix,
        "description": "Rows represent Ground Truth labels; Columns represent XGBoost Predicted labels."
    }

    feature_eval_data = {
        "gain_importance": feature_importance_list,
        "shap_importance": shap_importance,
        "top_features": [f["feature"] for f in feature_importance_list[:5]],
        "methodology": "TreeSHAP (TreeExplainer) and Gini impurity reduction across multi-class trees."
    }

    # Write evaluation files
    with open(os.path.join(EVAL_DIR, "xgboost_evaluation.json"), "w") as f:
        json.dump(eval_summary, f, indent=2)

    with open(os.path.join(EVAL_DIR, "xgboost_confusion_matrix.json"), "w") as f:
        json.dump(conf_matrix_data, f, indent=2)

    with open(os.path.join(EVAL_DIR, "xgboost_feature_importance.json"), "w") as f:
        json.dump(feature_eval_data, f, indent=2)

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
        "top_features": [f["feature"] for f in feature_importance_list[:5]],
        "evaluation_type": "DEVELOPMENT_EVALUATION",
        "production_benchmark_distinction": eval_summary["production_benchmark_distinction"]
    }

    with open(METADATA_OUTPUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nModel successfully saved to: {MODEL_OUTPUT_PATH}")
    print(f"Evaluation report saved to: {os.path.join(EVAL_DIR, 'xgboost_evaluation.json')}")
    print(f"SHAP feature importance saved to: {os.path.join(EVAL_DIR, 'xgboost_feature_importance.json')}")
    return metadata


if __name__ == "__main__":
    train_xgboost()
