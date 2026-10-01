import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.security_event import SecurityEvent
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.incident import (
    IncidentResponse,
    IncidentDetailResponse,
    IncidentDecisionRequest,
    IncidentInvestigateResponse,
    TimelineItem,
    EnrichedEventResponse,
)
from backend.app.schemas.detection import DetectionResponse
from backend.app.schemas.anomaly import AnomalyResponse
from backend.app.schemas.mitre import MitreTechniqueResponse
from backend.app.services.correlation_engine import correlation_engine
from backend.app.services.ai_analyst import ai_analyst

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("", response_model=List[IncidentResponse])
def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity.upper())

    incidents = query.order_by(desc(Incident.updated_at)).limit(limit).all()

    response = []
    for inc in incidents:
        event_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).count()
        mitre_techs = (
            db.query(MitreTechnique.technique_id)
            .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
            .filter(IncidentMitreMapping.incident_id == inc.id)
            .all()
        )
        tech_list = [t[0] for t in mitre_techs]

        response.append(IncidentResponse(
            id=inc.id,
            incident_id=inc.incident_id,
            title=inc.title,
            severity=inc.severity,
            risk_score=inc.risk_score,
            status=inc.status,
            source_ip=inc.source_ip,
            user=inc.user,
            hostname=inc.hostname,
            summary=inc.summary,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            event_count=event_count,
            mitre_techniques=tech_list,
        ))
    return response


@router.get("/{incident_id_or_str}", response_model=IncidentDetailResponse)
def get_incident_detail(incident_id_or_str: str, db: Session = Depends(get_db)):
    if incident_id_or_str.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_id_or_str)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_id_or_str).first()

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id_or_str}' not found")

    # Fetch ordered timeline
    timeline_raw = correlation_engine.get_incident_timeline(db, incident.id)
    timeline = [TimelineItem(**t) for t in timeline_raw]

    # Fetch related events
    events = (
        db.query(SecurityEvent)
        .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
        .filter(IncidentEvent.incident_id == incident.id)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )

    enriched_events = []
    for ev in events:
        dets = [DetectionResponse.model_validate(d) for d in ev.detections]
        anoms = [AnomalyResponse.model_validate(a) for a in ev.anomalies]
        enriched_events.append(EnrichedEventResponse(
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
        ))

    # Fetch MITRE techniques
    mitre_techs = (
        db.query(MitreTechnique)
        .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
        .filter(IncidentMitreMapping.incident_id == incident.id)
        .all()
    )
    mitre_details = [MitreTechniqueResponse.model_validate(t) for t in mitre_techs]

    # Fetch audit logs
    audit_records = db.query(AuditLog).filter(AuditLog.incident_id == incident.id).order_by(desc(AuditLog.created_at)).all()
    audit_logs = [
        {
            "id": a.id,
            "action": a.action,
            "actor": a.actor,
            "details": a.details,
            "created_at": a.created_at.isoformat()
        }
        for a in audit_records
    ]

    # Fetch verification requests
    v_requests = [
        {
            "id": vr.id,
            "challenge_id": vr.challenge_id,
            "user_id": vr.user_id,
            "status": vr.status,
            "activity_summary": vr.activity_summary,
            "delivery_method": vr.delivery_method,
            "verification_url": f"/verify/{vr.challenge_id}",
            "created_at": vr.created_at.isoformat(),
            "expires_at": vr.expires_at.isoformat(),
            "responses": [
                {
                    "id": resp.id,
                    "response": resp.response,
                    "authenticated": resp.authenticated,
                    "verification_method": resp.verification_method,
                    "client_ip": resp.client_ip,
                    "responded_at": resp.responded_at.isoformat()
                }
                for resp in (vr.responses or [])
            ]
        }
        for vr in (incident.verification_requests or [])
    ]

    # Fetch response actions
    r_actions = [
        {
            "id": ra.id,
            "action": ra.action,
            "reason": ra.reason,
            "status": ra.status,
            "analyst_id": ra.analyst_id,
            "parameters": ra.parameters or {},
            "execution_log": ra.execution_log,
            "created_at": ra.created_at.isoformat(),
            "approved_at": ra.approved_at.isoformat() if ra.approved_at else None,
            "executed_at": ra.executed_at.isoformat() if ra.executed_at else None,
        }
        for ra in (incident.response_actions or [])
    ]

    evidence = {
        "source_ip": incident.source_ip,
        "affected_user": incident.user,
        "target_host": incident.hostname,
        "event_count": len(enriched_events),
        "mitre_count": len(mitre_details),
        "first_seen": enriched_events[0].timestamp.isoformat() if enriched_events else incident.created_at.isoformat(),
        "last_seen": enriched_events[-1].timestamp.isoformat() if enriched_events else incident.updated_at.isoformat(),
    }

    return IncidentDetailResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        source_ip=incident.source_ip,
        user=incident.user,
        hostname=incident.hostname,
        summary=incident.summary,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        event_count=len(enriched_events),
        mitre_techniques=[t.technique_id for t in mitre_techs],
        events=enriched_events,
        timeline=timeline,
        mitre_details=mitre_details,
        evidence=evidence,
        audit_logs=audit_logs,
        verification_requests=v_requests,
        response_actions=r_actions,
    )


@router.post("/{incident_id_or_str}/investigate", response_model=IncidentInvestigateResponse)
def trigger_investigation(incident_id_or_str: str, db: Session = Depends(get_db)):
    result = ai_analyst.investigate(db, incident_id_or_str)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return IncidentInvestigateResponse(**result)


@router.post("/{incident_id_or_str}/decision", response_model=IncidentResponse)
def make_analyst_decision(
    incident_id_or_str: str,
    payload: IncidentDecisionRequest,
    db: Session = Depends(get_db)
):
    if incident_id_or_str.isdigit():
        incident = db.query(Incident).filter(Incident.id == int(incident_id_or_str)).first()
    else:
        incident = db.query(Incident).filter(Incident.incident_id == incident_id_or_str).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    from backend.app.services.state_machine import validate_transition
    if not validate_transition(incident.status, payload.status):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid state transition from '{incident.status}' to '{payload.status}'"
        )

    old_status = incident.status
    incident.status = payload.status
    incident.updated_at = datetime.datetime.utcnow()

    # Log action
    audit = AuditLog(
        incident_id=incident.id,
        action="ANALYST_DECISION",
        actor=payload.actor or "analyst",
        details={
            "old_status": old_status,
            "new_status": payload.status,
            "action_notes": payload.action_notes,
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(incident)

    event_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id).count()
    mitre_techs = (
        db.query(MitreTechnique.technique_id)
        .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
        .filter(IncidentMitreMapping.incident_id == incident.id)
        .all()
    )

    return IncidentResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        severity=incident.severity,
        risk_score=incident.risk_score,
        status=incident.status,
        source_ip=incident.source_ip,
        user=incident.user,
        hostname=incident.hostname,
        summary=incident.summary,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
        event_count=event_count,
        mitre_techniques=[t[0] for t in mitre_techs],
    )
