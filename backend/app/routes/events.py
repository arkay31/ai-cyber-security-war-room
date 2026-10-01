import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.security_event import SecurityEvent
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.schemas.security_event import (
    SecurityEventCreate,
    SecurityEventResponse,
    SecurityEventBulkCreate,
)
from backend.app.schemas.detection import DetectionResponse
from backend.app.schemas.anomaly import AnomalyResponse
from backend.app.schemas.incident import EnrichedEventResponse
from backend.app.ml.inference import inference_engine
from backend.app.services.correlation_engine import correlation_engine
from backend.app.services.synthetic_generator import SyntheticGenerator

router = APIRouter(prefix="/api", tags=["Events & Detections"])


@router.get("/events", response_model=List[EnrichedEventResponse])
def get_events(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if severity:
        query = query.filter(SecurityEvent.severity == severity.lower())
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.lower())
    if source_ip:
        query = query.filter(SecurityEvent.source_ip == source_ip)

    events = query.order_by(desc(SecurityEvent.timestamp)).offset(offset).limit(limit).all()

    result = []
    for ev in events:
        dets = [DetectionResponse.model_validate(d) for d in ev.detections]
        anoms = [AnomalyResponse.model_validate(a) for a in ev.anomalies]
        res_item = EnrichedEventResponse(
            id=ev.id,
            timestamp=ev.timestamp,
            source_ip=ev.source_ip,
            destination_ip=ev.destination_ip,
            source_port=ev.source_port,
            destination_port=ev.destination_port,
            protocol=ev.protocol,
            user=ev.user,
            hostname=ev.hostname,
            event_type=ev.event_type,
            severity=ev.severity,
            raw_data=ev.raw_data or {},
            created_at=ev.created_at,
            detections=dets,
            anomalies=anoms,
        )
        result.append(res_item)
    return result


@router.get("/events/{event_id}", response_model=EnrichedEventResponse)
def get_event_by_id(event_id: int, db: Session = Depends(get_db)):
    ev = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Security event not found")

    dets = [DetectionResponse.model_validate(d) for d in ev.detections]
    anoms = [AnomalyResponse.model_validate(a) for a in ev.anomalies]
    return EnrichedEventResponse(
        id=ev.id,
        timestamp=ev.timestamp,
        source_ip=ev.source_ip,
        destination_ip=ev.destination_ip,
        source_port=ev.source_port,
        destination_port=ev.destination_port,
        protocol=ev.protocol,
        user=ev.user,
        hostname=ev.hostname,
        event_type=ev.event_type,
        severity=ev.severity,
        raw_data=ev.raw_data or {},
        created_at=ev.created_at,
        detections=dets,
        anomalies=anoms,
    )


@router.post("/events", response_model=EnrichedEventResponse, status_code=201)
def ingest_single_event(payload: SecurityEventCreate, db: Session = Depends(get_db)):
    event = SecurityEvent(
        timestamp=payload.timestamp or datetime.datetime.utcnow(),
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        source_port=payload.source_port,
        destination_port=payload.destination_port,
        protocol=payload.protocol,
        user=payload.user,
        hostname=payload.hostname,
        event_type=payload.event_type,
        severity=payload.severity.lower(),
        raw_data=payload.raw_data or {},
        created_at=datetime.datetime.utcnow(),
    )
    db.add(event)
    db.flush()

    event_dict = payload.model_dump()
    ml_pred = inference_engine.predict_threat(event_dict)
    detection = Detection(
        event_id=event.id,
        model_name=ml_pred["model_name"],
        predicted_class=ml_pred["predicted_class"],
        confidence=ml_pred["confidence"],
        created_at=datetime.datetime.utcnow()
    )
    db.add(detection)

    anom_res = inference_engine.predict_anomaly(event_dict)
    anomaly = Anomaly(
        event_id=event.id,
        anomaly_score=anom_res["anomaly_score"],
        is_anomalous=anom_res["is_anomalous"],
        model_name=anom_res["model_name"],
        created_at=datetime.datetime.utcnow()
    )
    db.add(anomaly)
    db.flush()

    # Correlate event into incidents
    correlation_engine.correlate_event(db, event, detection, anomaly)
    db.commit()
    db.refresh(event)

    return EnrichedEventResponse(
        id=event.id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        source_port=event.source_port,
        destination_port=event.destination_port,
        protocol=event.protocol,
        user=event.user,
        hostname=event.hostname,
        event_type=event.event_type,
        severity=event.severity,
        raw_data=event.raw_data or {},
        created_at=event.created_at,
        detections=[DetectionResponse.model_validate(detection)],
        anomalies=[AnomalyResponse.model_validate(anomaly)],
    )


@router.post("/events/bulk", status_code=201)
def ingest_bulk_events(payload: SecurityEventBulkCreate, db: Session = Depends(get_db)):
    event_dicts = [e.model_dump() for e in payload.events]
    ingested = SyntheticGenerator.ingest_events(db, event_dicts)
    return {
        "status": "success",
        "ingested_count": len(ingested)
    }


@router.post("/events/synthetic/seed", status_code=201)
def seed_synthetic_scenarios(db: Session = Depends(get_db)):
    results = SyntheticGenerator.seed_all_scenarios(db)
    return {
        "status": "success",
        "details": results
    }


@router.post("/events/simulate-demo-attack", status_code=201)
def simulate_faculty_demo_attack(db: Session = Depends(get_db)):
    """
    Deterministic Faculty Demonstration Scenario:
    ACCOUNT TAKEOVER + PRIVILEGED ACCESS + SENSITIVE DATA ACCESS
    Runs the 7-event sequence through the full pipeline:
    Events -> XGBoost -> Isolation Forest -> Risk Engine -> Incident Correlation.
    """
    results = SyntheticGenerator.seed_faculty_demo(db)
    return results


@router.get("/detections", response_model=List[DetectionResponse])
def get_detections(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    dets = db.query(Detection).order_by(desc(Detection.created_at)).limit(limit).all()
    return [DetectionResponse.model_validate(d) for d in dets]


@router.get("/anomalies", response_model=List[AnomalyResponse])
def get_anomalies(
    is_anomalous_only: bool = Query(True),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    query = db.query(Anomaly)
    if is_anomalous_only:
        query = query.filter(Anomaly.is_anomalous == True)
    anoms = query.order_by(desc(Anomaly.anomaly_score)).limit(limit).all()
    return [AnomalyResponse.model_validate(a) for a in anoms]
