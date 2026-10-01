from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.incident import Incident
from backend.app.models.response_action import ResponseAction
from backend.app.schemas.response_action import (
    ResponseActionCreateRequest,
    ResponseActionExecuteRequest,
    ResponseActionResponse,
)
from backend.app.services.response_engine import response_engine

router = APIRouter(tags=["Response Actions"])


def _find_incident(db: Session, incident_id_or_str: str) -> Optional[Incident]:
    if incident_id_or_str.isdigit():
        return db.query(Incident).filter(Incident.id == int(incident_id_or_str)).first()
    return db.query(Incident).filter(Incident.incident_id == incident_id_or_str).first()


@router.get("/api/incidents/{incident_id_or_str}/responses", response_model=List[ResponseActionResponse])
def get_incident_response_actions(incident_id_or_str: str, db: Session = Depends(get_db)):
    """List all proposed and executed response actions for an incident."""
    incident = _find_incident(db, incident_id_or_str)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    actions = (
        db.query(ResponseAction)
        .filter(ResponseAction.incident_id == incident.id)
        .order_by(desc(ResponseAction.created_at))
        .all()
    )
    return actions


@router.post("/api/incidents/{incident_id_or_str}/responses", response_model=ResponseActionResponse)
def propose_response_action(
    incident_id_or_str: str,
    payload: ResponseActionCreateRequest,
    db: Session = Depends(get_db)
):
    """
    Propose a controlled response action (e.g., BLOCK_SOURCE_IP, ISOLATE_HOST).
    Creates a PENDING action that requires analyst confirmation to execute.
    """
    incident = _find_incident(db, incident_id_or_str)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        record = response_engine.propose_action(
            db=db,
            incident_id=incident.id,
            action=payload.action,
            reason=payload.reason,
            analyst_id=payload.analyst_id or "lead_analyst",
            parameters=payload.parameters,
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/responses/{action_id}/execute", response_model=ResponseActionResponse)
def execute_response_action(
    action_id: int,
    payload: ResponseActionExecuteRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst confirms and executes the proposed response action in safe SIMULATION mode.
    """
    try:
        record = response_engine.execute_action(
            db=db,
            action_id=action_id,
            analyst_id=payload.analyst_id or "lead_analyst",
            notes=payload.notes,
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/responses/{action_id}/reject", response_model=ResponseActionResponse)
def reject_response_action(
    action_id: int,
    payload: ResponseActionExecuteRequest,
    db: Session = Depends(get_db)
):
    """
    Analyst cancels/rejects the proposed response action.
    """
    try:
        record = response_engine.reject_action(
            db=db,
            action_id=action_id,
            analyst_id=payload.analyst_id or "lead_analyst",
            reason=payload.notes,
        )
        return record
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
