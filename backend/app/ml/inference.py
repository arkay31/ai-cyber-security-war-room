import os
import json
import logging
import joblib
import numpy as np
from typing import Dict, Any, Tuple, Optional
from backend.app.ml.preprocessor import CICIDSPreprocessor

logger = logging.getLogger(__name__)

# From backend/app/ml/inference.py -> backend/app/ml -> backend/app -> backend -> project_root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
MODELS_DIR = os.path.join(BASE_DIR, "models")
XGB_PATH = os.path.join(MODELS_DIR, "xgboost_detector.joblib")
ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.joblib")
ISO_PATH = os.path.join(MODELS_DIR, "isolation_forest.joblib")
ISO_META_PATH = os.path.join(MODELS_DIR, "anomaly_metadata.json")


class ModelInferenceEngine:
    def __init__(self):
        self.xgb_model = None
        self.label_encoder = None
        self.iso_model = None
        self.iso_min_score = -0.3
        self.iso_max_score = 0.2
        self.iso_threshold = 0.55
        self.benign_baseline = {}
        self.tree_explainer = None
        self.load_models()

    def load_models(self):
        try:
            if os.path.exists(XGB_PATH) and os.path.exists(ENCODER_PATH):
                self.xgb_model = joblib.load(XGB_PATH)
                self.label_encoder = joblib.load(ENCODER_PATH)
                logger.info("XGBoost model and LabelEncoder loaded successfully.")
            else:
                logger.warning(f"XGBoost model not found at {XGB_PATH}")

            if os.path.exists(ISO_PATH):
                self.iso_model = joblib.load(ISO_PATH)
                if os.path.exists(ISO_META_PATH):
                    with open(ISO_META_PATH, "r") as f:
                        meta = json.load(f)
                        cal = meta.get("calibration", {})
                        self.iso_min_score = cal.get("min_score", -0.3)
                        self.iso_max_score = cal.get("max_score", 0.2)
                        self.iso_threshold = cal.get("threshold", 0.55)
                        self.benign_baseline = meta.get("benign_feature_baseline", {})
                logger.info("Isolation Forest model loaded successfully.")
            else:
                logger.warning(f"Isolation Forest model not found at {ISO_PATH}")
        except Exception as e:
            logger.error(f"Error loading ML models: {e}")

    def get_tree_explainer(self):
        """Lazy-initialize TreeSHAP explainer for local feature attribution."""
        if self.tree_explainer is None and self.xgb_model is not None:
            try:
                import shap
                self.tree_explainer = shap.TreeExplainer(self.xgb_model)
                logger.info("TreeSHAP explainer initialized.")
            except Exception as e:
                logger.warning(f"Failed to initialize TreeSHAP explainer: {e}")
        return self.tree_explainer

    def explain_threat(self, event_dict: Dict[str, Any], predicted_class: str, top_k: int = 5) -> Dict[str, Any]:
        """
        Compute TreeSHAP local feature explanations for an XGBoost classification.
        Identifies exact feature contributions toward the predicted threat class.
        """
        import pandas as pd
        from backend.app.ml.preprocessor import SELECTED_FEATURES

        explainer = self.get_tree_explainer()
        features = CICIDSPreprocessor.event_to_features(event_dict)
        features_df = pd.DataFrame(features, columns=SELECTED_FEATURES)

        if explainer is None or self.label_encoder is None:
            return {
                "top_features": [],
                "summary": f"Threat classified as {predicted_class} using ensemble heuristic.",
                "method": "heuristic"
            }

        try:
            shap_vals = explainer.shap_values(features_df)
            classes = list(self.label_encoder.classes_)
            pred_idx = classes.index(predicted_class) if predicted_class in classes else 0

            if isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
                class_shaps = shap_vals[0, :, pred_idx]
            elif isinstance(shap_vals, list):
                class_shaps = shap_vals[pred_idx][0]
            else:
                class_shaps = shap_vals[0]

            feature_contributions = []
            for feat, val, s in zip(SELECTED_FEATURES, features_df.iloc[0], class_shaps):
                impact = "increases_threat_probability" if s > 0 else "decreases_threat_probability"
                feature_contributions.append({
                    "feature": feat,
                    "value": round(float(val), 2),
                    "shap_value": round(float(s), 4),
                    "impact": impact
                })

            feature_contributions.sort(key=lambda x: abs(x["shap_value"]), reverse=True)
            top_features = feature_contributions[:top_k]

            # Construct human-readable narrative
            key_feats = [f"{f['feature']} ({f['value']})" for f in top_features if f["shap_value"] > 0][:3]
            if key_feats:
                narrative = f"Prediction driven by {', '.join(key_feats)}."
            else:
                top_name = top_features[0]['feature'] if top_features else 'traffic pattern'
                narrative = f"Prediction primarily influenced by {top_name} characteristics."

            return {
                "top_features": top_features,
                "summary": narrative,
                "method": "TreeSHAP"
            }
        except Exception as e:
            logger.warning(f"TreeSHAP explanation failed: {e}")
            return {
                "top_features": [],
                "summary": f"Threat classified as {predicted_class}.",
                "method": "fallback"
            }

    def explain_anomaly(self, event_dict: Dict[str, Any], is_anomalous: bool, anomaly_score: float, top_k: int = 3) -> Dict[str, Any]:
        """
        Explain why an event was flagged as anomalous by computing z-scores
        against the benign normal traffic baseline.
        """
        import pandas as pd
        from backend.app.ml.preprocessor import SELECTED_FEATURES

        features = CICIDSPreprocessor.event_to_features(event_dict)
        features_df = pd.DataFrame(features, columns=SELECTED_FEATURES)

        if not self.benign_baseline:
            return {
                "deviations": [],
                "summary": "Anomalous flow signature identified." if is_anomalous else "Flow pattern matches benign baseline.",
                "method": "heuristic"
            }

        deviations = []
        for feat in SELECTED_FEATURES:
            base = self.benign_baseline.get(feat, {})
            mean = base.get("mean", 0.0)
            std = max(base.get("std", 1.0), 1.0)
            val = float(features_df[feat].iloc[0])
            z_score = float(np.clip((val - mean) / std, -15.0, 15.0))

            deviations.append({
                "feature": feat,
                "observed": round(val, 2),
                "benign_mean": round(mean, 2),
                "z_score": round(z_score, 2),
                "direction": "elevated" if z_score > 0 else "depressed"
            })

        deviations.sort(key=lambda x: abs(x["z_score"]), reverse=True)
        top_deviations = deviations[:top_k]

        significant = [d for d in top_deviations if abs(d["z_score"]) >= 1.5]
        if is_anomalous and significant:
            narrative = f"Anomalous flow: {significant[0]['feature']} is {abs(significant[0]['z_score'])} standard deviations {significant[0]['direction']} relative to normal traffic."
        elif is_anomalous:
            narrative = f"Multivariate anomalous isolation score ({anomaly_score:.2f}) exceeded calibrated baseline."
        else:
            narrative = "Flow features conform to normal enterprise traffic envelope."

        return {
            "deviations": top_deviations,
            "summary": narrative,
            "method": "z_score_deviation"
        }

    def predict_threat(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Classify attack category and return confidence score."""
        event_type = (event_dict.get("event_type") or "").lower()

        # If model is loaded, run feature vector prediction
        if self.xgb_model is not None and self.label_encoder is not None:
            try:
                import pandas as pd
                from backend.app.ml.preprocessor import SELECTED_FEATURES
                features = CICIDSPreprocessor.event_to_features(event_dict)
                features_df = pd.DataFrame(features, columns=SELECTED_FEATURES)
                probs = self.xgb_model.predict_proba(features_df)[0]
                pred_idx = int(np.argmax(probs))
                predicted_class = str(self.label_encoder.inverse_transform([pred_idx])[0])
                confidence = float(probs[pred_idx])

                # Context-aware rule override for explicit SOC events (e.g. brute force, port scan)
                if event_type in ["brute_force", "failed_login"] and predicted_class == "BENIGN":
                    predicted_class = "Brute Force"
                    confidence = 0.92
                elif event_type in ["port_scan", "reconnaissance"] and predicted_class == "BENIGN":
                    predicted_class = "PortScan"
                    confidence = 0.89
                elif event_type in ["privilege_escalation"] and predicted_class == "BENIGN":
                    predicted_class = "Privilege Escalation"
                    confidence = 0.94
                elif event_type in ["unusual_outbound_traffic", "data_exfiltration"] and predicted_class == "BENIGN":
                    predicted_class = "Data Exfiltration"
                    confidence = 0.88

                explanation = self.explain_threat(event_dict, predicted_class)

                return {
                    "model_name": "xgboost_detector",
                    "predicted_class": predicted_class,
                    "confidence": round(confidence, 4),
                    "feature_importance": explanation.get("top_features", []),
                    "explanation": explanation.get("summary", ""),
                    "explanation_method": explanation.get("method", "TreeSHAP")
                }
            except Exception as e:
                logger.warning(f"ML feature prediction failed: {e}. Using deterministic heuristic.")

        # Heuristic fallback if model not loaded or error occurred
        heuristic_mapping = {
            "brute_force": ("Brute Force", 0.94),
            "failed_login": ("Brute Force", 0.88),
            "port_scan": ("PortScan", 0.91),
            "reconnaissance": ("PortScan", 0.85),
            "ddos": ("DDoS", 0.95),
            "dos": ("DoS", 0.90),
            "privilege_escalation": ("Privilege Escalation", 0.93),
            "sensitive_file_access": ("Data Access", 0.87),
            "unusual_outbound_traffic": ("Exfiltration", 0.86),
            "lateral_movement": ("Lateral Movement", 0.89),
            "suspicious_process": ("Execution", 0.85),
            "successful_login": ("BENIGN", 0.95),
        }
        pred_class, conf = heuristic_mapping.get(event_type, ("BENIGN", 0.80))
        return {
            "model_name": "xgboost_detector",
            "predicted_class": pred_class,
            "confidence": conf,
            "feature_importance": [],
            "explanation": f"Classified as {pred_class} via rule signature.",
            "explanation_method": "heuristic"
        }

    def predict_anomaly(self, event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Compute anomaly score and anomalous flag."""
        event_type = (event_dict.get("event_type") or "").lower()

        if self.iso_model is not None:
            try:
                import pandas as pd
                from backend.app.ml.preprocessor import SELECTED_FEATURES
                features = CICIDSPreprocessor.event_to_features(event_dict)
                features_df = pd.DataFrame(features, columns=SELECTED_FEATURES)
                raw_score = float(self.iso_model.decision_function(features_df)[0])
                # Normalize raw score to [0.0, 1.0] (higher = more anomalous)
                span = max(self.iso_max_score - self.iso_min_score, 1e-6)
                normalized_score = 1.0 - ((raw_score - self.iso_min_score) / span)
                normalized_score = float(np.clip(normalized_score, 0.0, 1.0))

                # If event_type is inherently anomalous SOC activity, elevate score
                if event_type in ["privilege_escalation", "sensitive_file_access", "unusual_outbound_traffic", "brute_force", "port_scan"]:
                    normalized_score = max(normalized_score, 0.72)

                is_anomalous = bool(normalized_score >= self.iso_threshold)
                explanation = self.explain_anomaly(event_dict, is_anomalous, normalized_score)

                return {
                    "model_name": "isolation_forest",
                    "anomaly_score": round(normalized_score, 4),
                    "is_anomalous": is_anomalous,
                    "deviations": explanation.get("deviations", []),
                    "explanation": explanation.get("summary", ""),
                    "explanation_method": explanation.get("method", "z_score_deviation")
                }
            except Exception as e:
                logger.warning(f"Anomaly feature calculation failed: {e}. Using heuristic.")

        # Heuristic fallback
        anomaly_scores = {
            "privilege_escalation": 0.92,
            "sensitive_file_access": 0.85,
            "unusual_outbound_traffic": 0.87,
            "brute_force": 0.78,
            "port_scan": 0.74,
            "lateral_movement": 0.82,
            "suspicious_process": 0.81,
            "failed_login": 0.55,
            "successful_login": 0.12,
        }
        score = anomaly_scores.get(event_type, 0.20)
        is_anom = score >= 0.60
        return {
            "model_name": "isolation_forest",
            "anomaly_score": score,
            "is_anomalous": is_anom,
            "deviations": [],
            "explanation": "Heuristic anomaly score assignment." if is_anom else "Normal activity profile.",
            "explanation_method": "heuristic"
        }

    def predict_all(self, event_dict: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        detection = self.predict_threat(event_dict)
        anomaly = self.predict_anomaly(event_dict)
        return detection, anomaly


inference_engine = ModelInferenceEngine()
