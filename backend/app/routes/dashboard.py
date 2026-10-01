import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.database import get_db
from backend.app.models.security_event import SecurityEvent
from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    # Total events
    total_events = db.query(SecurityEvent).count()

    # Threats count (events with high/critical or non-benign ML)
    threats_count = (
        db.query(func.count(func.distinct(SecurityEvent.id)))
        .outerjoin(Detection, Detection.event_id == SecurityEvent.id)
        .filter(
            (SecurityEvent.severity.in_(["high", "critical"])) |
            (Detection.predicted_class.isnot(None) & (Detection.predicted_class != "BENIGN"))
        )
        .scalar()
    ) or 0

    # Incidents by severity
    critical_incidents = db.query(Incident).filter(
        Incident.severity == "CRITICAL",
        Incident.status.in_(["Investigating", "Contained"])
    ).count()

    high_incidents = db.query(Incident).filter(
        Incident.severity == "HIGH",
        Incident.status.in_(["Investigating", "Contained"])
    ).count()

    active_incidents = db.query(Incident).filter(
        Incident.status.in_(["Investigating", "Contained"])
    ).count()

    # Total anomalous events
    anomalies_count = db.query(Anomaly).filter(Anomaly.is_anomalous == True).count()

    # Distinct assets monitored (hostnames + destination IPs)
    distinct_hosts = {h[0] for h in db.query(SecurityEvent.hostname).filter(SecurityEvent.hostname.isnot(None)).all()}
    distinct_dest_ips = {ip[0] for ip in db.query(SecurityEvent.destination_ip).all()}
    assets_monitored = max(len(distinct_hosts | distinct_dest_ips), 1)

    # 24-hour threat activity trend
    now = datetime.datetime.utcnow()
    activity_buckets = []
    # Build 12 2-hour buckets covering the last 24h
    for i in range(11, -1, -1):
        bucket_time = now - datetime.timedelta(hours=i * 2)
        bucket_label = bucket_time.strftime("%H:00")
        window_start = bucket_time - datetime.timedelta(hours=2)

        ev_count = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp <= bucket_time
        ).count()

        anom_in_bucket = db.query(Anomaly).join(SecurityEvent, SecurityEvent.id == Anomaly.event_id).filter(
            Anomaly.is_anomalous == True,
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp <= bucket_time
        ).count()

        activity_buckets.append({
            "time": bucket_label,
            "threats": ev_count,
            "anomalies": anom_in_bucket,
        })

    # Recent incidents for dashboard table
    recent_inc_models = db.query(Incident).order_by(desc(Incident.updated_at)).limit(5).all()
    recent_incidents = []
    for inc in recent_inc_models:
        # Get highest confidence detection
        top_det = (
            db.query(Detection)
            .join(IncidentEvent, IncidentEvent.event_id == Detection.event_id)
            .filter(IncidentEvent.incident_id == inc.id)
            .order_by(desc(Detection.confidence))
            .first()
        )
        conf = int((top_det.confidence if top_det else 0.85) * 100)

        # Get first MITRE technique
        mitre_map = (
            db.query(MitreTechnique)
            .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
            .filter(IncidentMitreMapping.incident_id == inc.id)
            .first()
        )
        technique = mitre_map.technique_id if mitre_map else "T1078"

        recent_incidents.append({
            "id": inc.incident_id,
            "db_id": inc.id,
            "attack": inc.title,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "confidence": conf,
            "sourceIp": inc.source_ip or "Unknown",
            "target": inc.hostname or inc.user or "Internal Asset",
            "technique": technique,
            "timestamp": inc.updated_at.strftime("%I:%M %p"),
            "status": inc.status,
        })

    return {
        "total_security_events": total_events,
        "threats_today": threats_count if threats_count > 0 else total_events,
        "critical_incidents": critical_incidents,
        "high_severity_incidents": high_incidents,
        "active_incidents": active_incidents,
        "anomalies_detected": anomalies_count,
        "assets_monitored": assets_monitored,
        "threat_activity": activity_buckets,
        "recent_incidents": recent_incidents,
    }
