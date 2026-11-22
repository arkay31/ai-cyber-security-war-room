import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.database import get_db
from backend.app.ml.inference import XGB_PATH, ENCODER_PATH, ISO_PATH, inference_engine

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("")
def health_check(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    xgb_loaded = inference_engine.xgb_model is not None and inference_engine.label_encoder is not None
    iso_loaded = inference_engine.iso_model is not None

    xgb_file_exists = os.path.exists(XGB_PATH) and os.path.exists(ENCODER_PATH)
    iso_file_exists = os.path.exists(ISO_PATH)

    xgb_status = "loaded" if xgb_loaded else ("unloaded" if xgb_file_exists else "missing")
    iso_status = "loaded" if iso_loaded else ("unloaded" if iso_file_exists else "missing")

    # Explicit degraded status if model artifacts or DB are unavailable (Requirement 9)
    is_fully_healthy = (db_status == "ok") and xgb_loaded and iso_loaded
    if is_fully_healthy:
        overall_status = "healthy"
    elif db_status != "ok" and not xgb_loaded and not iso_loaded:
        overall_status = "unhealthy"
    else:
        overall_status = "degraded"

    return {
        "status": overall_status,
        "database": db_status,
        "models": {
            "xgboost_detector": xgb_status,
            "isolation_forest": iso_status
        },
        "services": {
            "ingestion": "active",
            "correlation_engine": "active",
            "risk_engine": "active",
            "mitre_service": "active",
            "ai_analyst": "active"
        }
    }
