import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import text

from backend.app.database import get_db
from backend.app.ml.inference import XGB_PATH, ISO_PATH

router = APIRouter(prefix="/api/health", tags=["Health"])


@router.get("")
def health_check(db: Session = Depends(get_db)):
    db_status = "ok"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"error: {str(e)}"

    xgb_present = os.path.exists(XGB_PATH)
    iso_present = os.path.exists(ISO_PATH)

    return {
        "status": "healthy" if db_status == "ok" else "degraded",
        "database": db_status,
        "models": {
            "xgboost_detector": "loaded" if xgb_present else "missing",
            "isolation_forest": "loaded" if iso_present else "missing"
        },
        "services": {
            "ingestion": "active",
            "correlation_engine": "active",
            "risk_engine": "active",
            "mitre_service": "active",
            "ai_analyst": "standby_placeholder"
        }
    }
