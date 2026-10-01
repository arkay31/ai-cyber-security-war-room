import datetime
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.database import get_db
from backend.app.models.security_event import SecurityEvent
from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping

router = APIRouter(prefix="/api", tags=["Analytics & Attack Graph & Reports"])


@router.get("/analytics")
def get_analytics(db: Session = Depends(get_db)):
    # 1. Attacks by type
    attack_counts = (
        db.query(Detection.predicted_class, func.count(Detection.id))
        .group_by(Detection.predicted_class)
        .all()
    )
    attacks_by_type = [
        {"name": row[0], "count": row[1]}
        for row in attack_counts if row[0]
    ]

    # 2. Severity distribution
    sev_counts = (
        db.query(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
        .all()
    )
    severity_distribution = [
        {"severity": row[0], "count": row[1]}
        for row in sev_counts
    ]

    # 3. Anomalies over time
    now = datetime.datetime.utcnow()
    anomalies_timeline = []
    for i in range(7, -1, -1):
        bucket_time = now - datetime.timedelta(hours=i * 3)
        lbl = bucket_time.strftime("%H:%M")
        start = bucket_time - datetime.timedelta(hours=3)
        cnt = db.query(Anomaly).join(SecurityEvent, SecurityEvent.id == Anomaly.event_id).filter(
            Anomaly.is_anomalous == True,
            SecurityEvent.timestamp >= start,
            SecurityEvent.timestamp <= bucket_time
        ).count()
        anomalies_timeline.append({"time": lbl, "anomalies": cnt})

    # 4. Confidence distribution
    detections = db.query(Detection.confidence).all()
    buckets = {"90-100%": 0, "80-89%": 0, "70-79%": 0, "<70%": 0}
    for d in detections:
        c = d[0] * 100
        if c >= 90:
            buckets["90-100%"] += 1
        elif c >= 80:
            buckets["80-89%"] += 1
        elif c >= 70:
            buckets["70-79%"] += 1
        else:
            buckets["<70%"] += 1

    confidence_dist = [{"range": k, "count": v} for k, v in buckets.items()]

    return {
        "attacks_by_type": attacks_by_type,
        "severity_distribution": severity_distribution,
        "anomalies_timeline": anomalies_timeline,
        "confidence_distribution": confidence_dist,
        "total_incidents": db.query(Incident).count(),
        "total_events": db.query(SecurityEvent).count(),
    }


@router.get("/attack-graph")
def get_attack_graph(incident_id: int = Query(None), db: Session = Depends(get_db)):
    """
    Generate graph nodes and edges for React Flow visualization.
    Nodes: Incident, Attacker IP, Target Host, User, Events, MITRE Techniques.
    """
    nodes = []
    edges = []
    node_ids = set()

    incidents_query = db.query(Incident)
    if incident_id:
        incidents_query = incidents_query.filter(Incident.id == incident_id)
    incidents = incidents_query.order_by(desc(Incident.updated_at)).limit(3).all()

    y_offset = 50
    for inc_idx, inc in enumerate(incidents):
        inc_node_id = f"inc-{inc.id}"
        if inc_node_id not in node_ids:
            nodes.append({
                "id": inc_node_id,
                "type": "incidentNode",
                "position": {"x": 350, "y": y_offset + (inc_idx * 280)},
                "data": {
                    "label": inc.incident_id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                    "type": "incident"
                }
            })
            node_ids.add(inc_node_id)

        # Attacker IP node
        if inc.source_ip:
            ip_node_id = f"ip-{inc.source_ip}"
            if ip_node_id not in node_ids:
                nodes.append({
                    "id": ip_node_id,
                    "position": {"x": 50, "y": y_offset + (inc_idx * 280)},
                    "data": {"label": inc.source_ip, "type": "source_ip"}
                })
                node_ids.add(ip_node_id)
            edges.append({
                "id": f"edge-{ip_node_id}-{inc_node_id}",
                "source": ip_node_id,
                "target": inc_node_id,
                "label": "originated from",
                "animated": True,
            })

        # Target Host / User node
        target_name = inc.hostname or "Internal Host"
        host_node_id = f"host-{target_name}"
        if host_node_id not in node_ids:
            nodes.append({
                "id": host_node_id,
                "position": {"x": 680, "y": y_offset + (inc_idx * 280)},
                "data": {"label": target_name, "type": "target_host"}
            })
            node_ids.add(host_node_id)
        edges.append({
            "id": f"edge-{inc_node_id}-{host_node_id}",
            "source": inc_node_id,
            "target": host_node_id,
            "label": "targets",
        })

        if inc.user:
            user_node_id = f"user-{inc.user}"
            if user_node_id not in node_ids:
                nodes.append({
                    "id": user_node_id,
                    "position": {"x": 680, "y": y_offset + (inc_idx * 280) + 90},
                    "data": {"label": f"User: {inc.user}", "type": "user"}
                })
                node_ids.add(user_node_id)
            edges.append({
                "id": f"edge-{inc_node_id}-{user_node_id}",
                "source": inc_node_id,
                "target": user_node_id,
                "label": "abused account",
            })

        # MITRE Technique nodes
        mitre_techs = (
            db.query(MitreTechnique)
            .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
            .filter(IncidentMitreMapping.incident_id == inc.id)
            .all()
        )
        for t_idx, tech in enumerate(mitre_techs):
            tech_node_id = f"tech-{tech.technique_id}"
            if tech_node_id not in node_ids:
                nodes.append({
                    "id": tech_node_id,
                    "position": {"x": 350 + (t_idx * 160) - 80, "y": y_offset + (inc_idx * 280) + 160},
                    "data": {"label": f"{tech.technique_id}: {tech.name}", "type": "mitre"}
                })
                node_ids.add(tech_node_id)
            edges.append({
                "id": f"edge-{inc_node_id}-{tech_node_id}",
                "source": inc_node_id,
                "target": tech_node_id,
                "label": "ATT&CK",
            })

    return {"nodes": nodes, "edges": edges}


@router.get("/reports")
def get_incident_reports(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(desc(Incident.updated_at)).all()
    reports = []
    for inc in incidents:
        events = (
            db.query(SecurityEvent)
            .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
            .filter(IncidentEvent.incident_id == inc.id)
            .all()
        )
        mitre_techs = (
            db.query(MitreTechnique)
            .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
            .filter(IncidentMitreMapping.incident_id == inc.id)
            .all()
        )
        reports.append({
            "report_id": f"REP-{inc.incident_id}",
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity,
            "risk_score": inc.risk_score,
            "status": inc.status,
            "source_ip": inc.source_ip,
            "user": inc.user,
            "hostname": inc.hostname,
            "summary": inc.summary,
            "event_count": len(events),
            "mitre_techniques": [f"{t.technique_id}: {t.name} ({t.tactic})" for t in mitre_techs],
            "generated_at": datetime.datetime.utcnow().isoformat(),
        })
    return reports
