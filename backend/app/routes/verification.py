import datetime
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models.incident import Incident
from backend.app.models.verification import VerificationRequest, VerificationResponse
from backend.app.models.audit_log import AuditLog
from backend.app.schemas.verification import (
    VerificationCreateRequest,
    VerificationRequestResponse,
    PublicChallengeDetailResponse,
    UserVerifySubmitRequest,
)

router = APIRouter(tags=["User Verification"])


def _find_incident(db: Session, incident_id_or_str: str) -> Optional[Incident]:
    if incident_id_or_str.isdigit():
        return db.query(Incident).filter(Incident.id == int(incident_id_or_str)).first()
    return db.query(Incident).filter(Incident.incident_id == incident_id_or_str).first()


@router.post("/api/incidents/{incident_id_or_str}/verification", response_model=VerificationRequestResponse)
def create_verification_request(
    incident_id_or_str: str,
    payload: VerificationCreateRequest,
    db: Session = Depends(get_db)
):
    """
    SOC Analyst initiates a Human-in-the-Loop User Verification challenge.
    Dispatches challenge URL and transitions incident to AWAITING_USER_VERIFICATION.
    """
    incident = _find_incident(db, incident_id_or_str)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    target_user = payload.user_id or incident.user or "primary_user"
    challenge_id = uuid.uuid4().hex[:16]
    now = datetime.datetime.utcnow()
    expires_at = now + datetime.timedelta(minutes=payload.expires_in_minutes)

    # Safe summary for non-technical user challenge
    safe_summary = payload.activity_summary or (
        f"Login and privileged administrative activity detected on system '{incident.hostname or 'Enterprise Host'}' "
        f"originating from IP address '{incident.source_ip or 'External Gateway'}'."
    )

    req = VerificationRequest(
        incident_id=incident.id,
        user_id=target_user,
        challenge_id=challenge_id,
        status="PENDING",
        activity_summary=safe_summary,
        requested_by="analyst",
        delivery_method=payload.delivery_method,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(req)

    # Transition incident state
    incident.status = "AWAITING_USER_VERIFICATION"
    incident.updated_at = now
    db.add(incident)

    # Create audit log
    audit = AuditLog(
        incident_id=incident.id,
        action="VERIFICATION_REQUESTED",
        actor="analyst",
        details={
            "challenge_id": challenge_id,
            "target_user": target_user,
            "delivery_method": payload.delivery_method,
            "expires_at": expires_at.isoformat(),
        }
    )
    db.add(audit)
    db.commit()
    db.refresh(req)

    return VerificationRequestResponse(
        id=req.id,
        incident_id=req.incident_id,
        user_id=req.user_id,
        challenge_id=req.challenge_id,
        status=req.status,
        activity_summary=req.activity_summary,
        requested_by=req.requested_by,
        delivery_method=req.delivery_method,
        verification_url=f"/verify/{req.challenge_id}",
        created_at=req.created_at,
        expires_at=req.expires_at,
        responses=[],
    )


@router.get("/api/incidents/{incident_id_or_str}/verification", response_model=List[VerificationRequestResponse])
def get_incident_verifications(incident_id_or_str: str, db: Session = Depends(get_db)):
    """Fetch all verification challenges and user responses for an incident."""
    incident = _find_incident(db, incident_id_or_str)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    requests = (
        db.query(VerificationRequest)
        .filter(VerificationRequest.incident_id == incident.id)
        .order_by(desc(VerificationRequest.created_at))
        .all()
    )

    now = datetime.datetime.utcnow()
    results = []
    for r in requests:
        # Check if expired
        if r.status == "PENDING" and now > r.expires_at:
            r.status = "EXPIRED"
            db.add(r)
            if incident.status == "AWAITING_USER_VERIFICATION":
                incident.status = "VERIFICATION_EXPIRED"
                db.add(incident)
            db.commit()

        results.append(VerificationRequestResponse(
            id=r.id,
            incident_id=r.incident_id,
            user_id=r.user_id,
            challenge_id=r.challenge_id,
            status=r.status,
            activity_summary=r.activity_summary,
            requested_by=r.requested_by,
            delivery_method=r.delivery_method,
            verification_url=f"/verify/{r.challenge_id}",
            created_at=r.created_at,
            expires_at=r.expires_at,
            responses=r.responses or [],
        ))
    return results


@router.get("/api/verify/{challenge_id}", response_model=PublicChallengeDetailResponse)
def get_challenge_details(challenge_id: str, db: Session = Depends(get_db)):
    """
    Public endpoint for the User Verification page.
    Renders safe, non-sensitive summary of activity for the user to confirm or deny.
    """
    req = db.query(VerificationRequest).filter(VerificationRequest.challenge_id == challenge_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Verification challenge not found or link is invalid.")

    now = datetime.datetime.utcnow()
    is_expired = now > req.expires_at

    if is_expired and req.status == "PENDING":
        req.status = "EXPIRED"
        incident = db.query(Incident).filter(Incident.id == req.incident_id).first()
        if incident and incident.status == "AWAITING_USER_VERIFICATION":
            incident.status = "VERIFICATION_EXPIRED"
            db.add(incident)
        db.add(req)
        db.commit()

    incident = db.query(Incident).filter(Incident.id == req.incident_id).first()
    inc_identifier = incident.incident_id if incident else f"INC-{req.incident_id}"

    return PublicChallengeDetailResponse(
        challenge_id=req.challenge_id,
        incident_id=inc_identifier,
        user_id=req.user_id,
        status=req.status,
        activity_summary=req.activity_summary,
        created_at=req.created_at,
        expires_at=req.expires_at,
        is_expired=is_expired,
        question="Did you perform this activity?",
    )


@router.post("/api/verify/{challenge_id}/respond", response_model=PublicChallengeDetailResponse)
def submit_challenge_response(
    challenge_id: str,
    payload: UserVerifySubmitRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    User responds to the verification challenge.
    Handles 'CONFIRMED' (Yes, it was me) or 'DENIED' (No, I did not do this).
    Updates incident state and generates audit log.
    """
    req = db.query(VerificationRequest).filter(VerificationRequest.challenge_id == challenge_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Verification challenge not found.")

    now = datetime.datetime.utcnow()
    if now > req.expires_at or req.status == "EXPIRED":
        req.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=400, detail="This verification challenge has expired.")

    if req.status in ["CONFIRMED", "DENIED"]:
        raise HTTPException(status_code=400, detail=f"Challenge already completed with status: {req.status}")

    user_choice = payload.response.upper().strip()
    if user_choice not in ["CONFIRMED", "DENIED"]:
        raise HTTPException(status_code=400, detail="Response must be either 'CONFIRMED' or 'DENIED'")

    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "Unknown Device")

    # Record response
    v_resp = VerificationResponse(
        verification_request_id=req.id,
        response=user_choice,
        authenticated=True,
        verification_method=payload.verification_method or "DEMO_PORTAL",
        client_ip=client_ip,
        user_agent=user_agent[:255] if user_agent else None,
        responded_at=now,
    )
    db.add(v_resp)

    incident = db.query(Incident).filter(Incident.id == req.incident_id).first()
    req.status = user_choice

    if user_choice == "CONFIRMED":
        # User confirmed activity: do NOT close automatically, set to USER_CONFIRMED for analyst review
        if incident:
            incident.status = "USER_CONFIRMED"
            incident.updated_at = now
            db.add(incident)

        audit = AuditLog(
            incident_id=req.incident_id,
            action="USER_CONFIRMED",
            actor=f"user:{req.user_id}",
            details={
                "challenge_id": challenge_id,
                "client_ip": client_ip,
                "action": "User verified activity was legitimate.",
                "next_step": "Awaiting SOC analyst determination to Mark as Legitimate or Continue Investigation."
            }
        )
        db.add(audit)

    else:
        # User denied activity: confirmed compromise! Increase severity and risk score
        if incident:
            incident.status = "USER_DENIED"
            incident.severity = "CRITICAL"
            incident.risk_score = min(100.0, incident.risk_score + 15.0)
            incident.updated_at = now
            db.add(incident)

        audit = AuditLog(
            incident_id=req.incident_id,
            action="USER_DENIED",
            actor=f"user:{req.user_id}",
            details={
                "challenge_id": challenge_id,
                "client_ip": client_ip,
                "alert": "User explicitly denied performing activity! Account compromise confirmed.",
                "recommendation": "Revoke sessions, isolate host, reset credentials."
            }
        )
        db.add(audit)

    db.commit()
    db.refresh(req)

    inc_identifier = incident.incident_id if incident else f"INC-{req.incident_id}"
    return PublicChallengeDetailResponse(
        challenge_id=req.challenge_id,
        incident_id=inc_identifier,
        user_id=req.user_id,
        status=req.status,
        activity_summary=req.activity_summary,
        created_at=req.created_at,
        expires_at=req.expires_at,
        is_expired=False,
        question="Did you perform this activity?",
    )
