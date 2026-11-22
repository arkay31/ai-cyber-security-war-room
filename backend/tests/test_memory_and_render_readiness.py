import os
import json
import pytest
import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.database import Base
from backend.app.models.knowledge import KnowledgeEmbedding
from backend.app.ml.inference import (
    ModelInferenceEngine,
    inference_engine,
    XGB_PATH,
    ENCODER_PATH,
    ISO_PATH,
    ISO_META_PATH
)
from backend.app.routes.health import health_check
from scripts.ingest_knowledge import ingest_knowledge, chunk_text


def test_model_paths_and_artifacts():
    """Verify that model files exist on disk and inference_engine has loaded them."""
    assert os.path.exists(XGB_PATH), f"XGBoost model missing at {XGB_PATH}"
    assert os.path.exists(ENCODER_PATH), f"LabelEncoder missing at {ENCODER_PATH}"
    assert os.path.exists(ISO_PATH), f"IsolationForest missing at {ISO_PATH}"
    assert os.path.exists(ISO_META_PATH), f"Anomaly metadata missing at {ISO_META_PATH}"

    assert inference_engine.xgb_model is not None, "XGBoost model failed to load into memory"
    assert inference_engine.label_encoder is not None, "LabelEncoder failed to load into memory"
    assert inference_engine.iso_model is not None, "Isolation Forest failed to load into memory"

    # Test real threat prediction
    event = {
        "event_type": "port_scan",
        "source_ip": "192.168.1.100",
        "destination_port": 80,
        "raw_data": {"Destination Port": 80, "Flow Duration": 5000}
    }
    threat_res = inference_engine.predict_threat(event)
    assert threat_res["model_name"] == "xgboost_detector"
    assert threat_res["model_status"] == "loaded"
    assert threat_res["confidence"] > 0.0
    assert len(threat_res["feature_importance"]) > 0

    # Test real anomaly prediction
    anom_res = inference_engine.predict_anomaly(event)
    assert anom_res["model_name"] == "isolation_forest"
    assert anom_res["model_status"] == "loaded"
    assert 0.0 <= anom_res["anomaly_score"] <= 1.0


def test_degraded_model_fallback_transparency():
    """Verify Requirement 9: Never silently replace missing models with fake predictions."""
    dummy_engine = ModelInferenceEngine()
    dummy_engine.xgb_model = None
    dummy_engine.label_encoder = None
    dummy_engine.iso_model = None

    event = {"event_type": "port_scan"}
    threat_res = dummy_engine.predict_threat(event)
    assert threat_res["model_status"] == "degraded_fallback"
    assert "heuristic_fallback" in threat_res["model_name"]
    assert "unavailable" in threat_res["explanation"]

    anom_res = dummy_engine.predict_anomaly(event)
    assert anom_res["model_status"] == "degraded_fallback"
    assert "heuristic_fallback" in anom_res["model_name"]
    assert "unavailable" in anom_res["explanation"]


def test_health_check_reporting():
    """Verify that health check reports real component status and degraded states."""
    test_engine = create_engine("sqlite:///:memory:")
    TestSession = sessionmaker(bind=test_engine)
    db = TestSession()

    res = health_check(db=db)
    assert res["database"] == "ok"
    assert res["status"] == "healthy"
    assert res["models"]["xgboost_detector"] == "loaded"
    assert res["models"]["isolation_forest"] == "loaded"

    # Test degraded health when model is unloaded
    saved_xgb = inference_engine.xgb_model
    try:
        inference_engine.xgb_model = None
        degraded_res = health_check(db=db)
        assert degraded_res["status"] == "degraded"
        assert degraded_res["models"]["xgboost_detector"] == "unloaded"
    finally:
        inference_engine.xgb_model = saved_xgb


def test_idempotent_ingestion_with_precomputed_embeddings():
    """Verify Requirement 5 & 6: Ingestion is idempotent and uses precomputed embeddings."""
    test_engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(bind=test_engine)
    db = TestSession()

    # First run: should insert precomputed chunks
    res1 = ingest_knowledge(db=db)
    assert res1["status"] == "success"
    assert res1["inserted"] == 42
    assert res1["total"] == 42

    # Second run: must detect existing corpus and skip (idempotent)
    res2 = ingest_knowledge(db=db)
    assert res2["status"] == "already_ingested"
    assert res2["inserted"] == 0
    assert res2["total"] == 42

    # Verify embeddings in DB
    records = db.query(KnowledgeEmbedding).all()
    assert len(records) == 42
    for r in records:
        assert len(r.embedding) == 384
        assert any(x != 0.0 for x in r.embedding)  # Vector is dense and non-zero
