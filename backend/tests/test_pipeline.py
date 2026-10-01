import pytest
from backend.app.ml.inference import inference_engine
from backend.app.services.risk_engine import risk_engine
from backend.app.services.mitre_service import MitreService


def test_ml_threat_inference():
    # Test Brute Force event feature inference
    event = {
        "event_type": "failed_login",
        "severity": "high",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "destination_port": 22,
        "protocol": "SSH",
        "raw_data": {
            "Destination Port": 22,
            "Flow Duration": 2500,
            "Total Fwd Packets": 10,
            "Total Backward Packets": 6,
        }
    }
    detection = inference_engine.predict_threat(event)
    assert "predicted_class" in detection
    assert "confidence" in detection
    assert 0.0 <= detection["confidence"] <= 1.0


def test_anomaly_inference():
    event = {
        "event_type": "sensitive_file_access",
        "severity": "critical",
        "source_ip": "10.0.0.15",
        "destination_ip": "203.0.113.88",
        "raw_data": {
            "Flow Duration": 500,
            "Total Length of Fwd Packets": 15000000.0,
        }
    }
    anomaly = inference_engine.predict_anomaly(event)
    assert "anomaly_score" in anomaly
    assert "is_anomalous" in anomaly
    assert 0.0 <= anomaly["anomaly_score"] <= 1.0


def test_risk_scoring_formula():
    event = {
        "severity": "critical",
        "user": "root",
        "hostname": "finance-srv01"
    }
    detection = {"predicted_class": "Brute Force", "confidence": 0.95}
    anomaly = {"anomaly_score": 0.88}

    res = risk_engine.calculate_event_risk(event, detection, anomaly)
    assert "risk_score" in res
    assert "severity" in res
    assert 0.0 <= res["risk_score"] <= 100.0
    assert res["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    # For critical root attack, risk should be high or critical
    assert res["risk_score"] >= 70.0


def test_mitre_mapping():
    techs = MitreService.map_event_to_techniques("failed_login", "Brute Force")
    assert "T1110" in techs

    techs_scan = MitreService.map_event_to_techniques("port_scan", "PortScan")
    assert "T1046" in techs_scan
