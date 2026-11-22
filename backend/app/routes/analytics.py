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
    # 1. Attacks by type from ML detections
    attack_counts = (
        db.query(Detection.predicted_class, func.count(Detection.id))
        .group_by(Detection.predicted_class)
        .all()
    )
    attacks_by_type = [
        {"name": row[0], "count": row[1]}
        for row in attack_counts if row[0]
    ]

    # 2. Severity distribution (normalized uppercase)
    sev_counts = (
        db.query(func.upper(Incident.severity), func.count(Incident.id))
        .group_by(func.upper(Incident.severity))
        .all()
    )
    sev_map = {row[0]: row[1] for row in sev_counts if row[0]}
    # Standardize tiers
    standard_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    severity_distribution = [
        {"severity": s, "count": sev_map.get(s, 0)}
        for s in standard_severities
        if sev_map.get(s, 0) > 0 or len(sev_map) == 0
    ]
    # Add any other non-standard severity if present in DB
    for s, count in sev_map.items():
        if s not in standard_severities and count > 0:
            severity_distribution.append({"severity": s, "count": count})

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
        if d[0] is not None:
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
    Implements a 4-column structured topology to avoid edge/label overlaps:
    Col 1 (x=60): Adversary IPs
    Col 2 (x=400): Correlated Incidents
    Col 3 (x=760): Target Hosts & Abused Users
    Col 4 (x=1120): Associated MITRE ATT&CK Techniques
    """
    nodes = []
    edges = []
    node_ids = set()

    incidents_query = db.query(Incident)
    if incident_id:
        incidents_query = incidents_query.filter(Incident.id == incident_id)
    incidents = incidents_query.order_by(desc(Incident.updated_at)).limit(4).all()

    y_offset = 60
    v_spacing = 300

    for inc_idx, inc in enumerate(incidents):
        base_y = y_offset + (inc_idx * v_spacing)
        inc_node_id = f"inc-{inc.id}"

        # Count events for this incident
        event_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id).count()

        # 1. Incident node (Column 2)
        if inc_node_id not in node_ids:
            nodes.append({
                "id": inc_node_id,
                "type": "default",
                "position": {"x": 400, "y": base_y},
                "data": {
                    "label": inc.incident_id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                    "status": inc.status,
                    "type": "incident",
                    "source_ip": inc.source_ip,
                    "hostname": inc.hostname,
                    "user": inc.user,
                    "event_count": event_count,
                    "summary": inc.summary,
                }
            })
            node_ids.add(inc_node_id)

        # 2. Attacker Source IP node (Column 1)
        if inc.source_ip:
            ip_node_id = f"ip-{inc.source_ip}"
            if ip_node_id not in node_ids:
                nodes.append({
                    "id": ip_node_id,
                    "position": {"x": 60, "y": base_y},
                    "data": {
                        "label": inc.source_ip,
                        "type": "source_ip",
                        "title": "Adversary Source IP",
                        "incident_id": inc.incident_id
                    }
                })
                node_ids.add(ip_node_id)

            edges.append({
                "id": f"edge-{ip_node_id}-{inc_node_id}",
                "source": ip_node_id,
                "target": inc_node_id,
                "label": "inbound attack",
                "animated": True,
            })

        # 3. Target Host node (Column 3)
        target_name = inc.hostname or "Internal Host"
        host_node_id = f"host-{target_name}"
        if host_node_id not in node_ids:
            nodes.append({
                "id": host_node_id,
                "position": {"x": 760, "y": base_y},
                "data": {
                    "label": target_name,
                    "type": "target_host",
                    "title": "Target Endpoint / Asset",
                    "status": inc.status
                }
            })
            node_ids.add(host_node_id)

        edges.append({
            "id": f"edge-{inc_node_id}-{host_node_id}",
            "source": inc_node_id,
            "target": host_node_id,
            "label": "targets host",
        })

        # 4. Abused User node (Column 3 offset)
        if inc.user:
            user_node_id = f"user-{inc.user}"
            if user_node_id not in node_ids:
                nodes.append({
                    "id": user_node_id,
                    "position": {"x": 760, "y": base_y + 110},
                    "data": {
                        "label": f"User: {inc.user}",
                        "type": "user",
                        "title": "Compromised Account",
                        "username": inc.user,
                        "incident_id": inc.incident_id
                    }
                })
                node_ids.add(user_node_id)

            edges.append({
                "id": f"edge-{inc_node_id}-{user_node_id}",
                "source": inc_node_id,
                "target": user_node_id,
                "label": "abused user",
            })

        # 5. MITRE Technique nodes (Column 4, stacked vertically)
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
                    "position": {"x": 1120, "y": base_y + (t_idx * 75)},
                    "data": {
                        "label": f"{tech.technique_id}: {tech.name}",
                        "technique_id": tech.technique_id,
                        "name": tech.name,
                        "tactic": tech.tactic,
                        "description": tech.description,
                        "type": "mitre",
                        "url": f"https://attack.mitre.org/techniques/{tech.technique_id.replace('.', '/')}/"
                    }
                })
                node_ids.add(tech_node_id)

            edges.append({
                "id": f"edge-{inc_node_id}-{tech_node_id}",
                "source": inc_node_id,
                "target": tech_node_id,
                "label": tech.tactic or "ATT&CK",
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
            "incident_created_at": inc.created_at.isoformat() if inc.created_at else None,
            "incident_updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
            "generated_at": datetime.datetime.utcnow().isoformat(),
        })
    return reports


@router.get("/analytics/ml-model-evaluation")
def get_ml_model_evaluation():
    """
    Returns verified evaluation reports, confusion matrices, SHAP feature attributions,
    and anomaly distributions for both the supervised XGBoost Threat Classifier and
    unsupervised Isolation Forest Anomaly Detector.
    """
    import os
    import json
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    eval_dir = os.path.join(base_dir, "models", "evaluation")

    def load_eval_json(fname: str) -> Dict[str, Any]:
        p = os.path.join(eval_dir, fname)
        if os.path.exists(p):
            with open(p, "r") as f:
                return json.load(f)
        return {}

    return {
        "status": "ready",
        "models": {
            "xgboost": load_eval_json("xgboost_evaluation.json"),
            "xgboost_feature_importance": load_eval_json("xgboost_feature_importance.json"),
            "xgboost_confusion_matrix": load_eval_json("xgboost_confusion_matrix.json"),
            "isolation_forest": load_eval_json("anomaly_evaluation.json")
        },
        "evaluation_scope": "CICIDS2017 Stratified Flow Dataset",
        "production_notice": (
            "Model metrics are computed against held-out validation and test splits. "
            "Production SOC deployment integrates human analyst approval and real-time TreeSHAP transparency."
        )
    }


@router.get("/analytics/rag-evaluation")
def get_rag_evaluation(db: Session = Depends(get_db)):
    """
    Execute quantitative RAG evaluation measuring Precision@K, MRR, and retrieval latency
    across standard MITRE ATT&CK attack queries against PostgreSQL pgvector.
    """
    from backend.app.services.rag_service import rag_service
    return rag_service.evaluate_rag_retrieval(db)
