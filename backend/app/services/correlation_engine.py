import datetime
import logging
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.security_event import SecurityEvent
from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping
from backend.app.models.audit_log import AuditLog
from backend.app.services.risk_engine import risk_engine
from backend.app.services.mitre_service import MitreService
from backend.app.config import settings

logger = logging.getLogger(__name__)


class CorrelationEngine:
    @staticmethod
    def _generate_incident_id(db: Session) -> str:
        count = db.query(Incident).count() + 1
        year = datetime.datetime.utcnow().year
        return f"INC-{year}-{count:04d}"

    @staticmethod
    def _format_event_description(event: SecurityEvent, detection: Optional[Detection], anomaly: Optional[Anomaly]) -> str:
        etype = event.event_type.replace("_", " ").title()
        user_info = f" on user '{event.user}'" if event.user else ""
        host_info = f" on host '{event.hostname}'" if event.hostname else ""
        ip_info = f" from {event.source_ip} to {event.destination_ip}:{event.destination_port or ''}"

        pred_info = f" [ML: {detection.predicted_class} ({int(detection.confidence * 100)}%)]" if detection and detection.predicted_class != "BENIGN" else ""
        anom_info = f" [Anomaly Score: {anomaly.anomaly_score:.2f}]" if anomaly and anomaly.is_anomalous else ""

        return f"{etype}{user_info}{host_info}{ip_info}{pred_info}{anom_info}"

    @staticmethod
    def correlate_event(
        db: Session,
        event: SecurityEvent,
        detection: Optional[Detection] = None,
        anomaly: Optional[Anomaly] = None,
    ) -> Optional[Incident]:
        """
        Correlate a security event to an existing active incident or create a new incident
        if the event indicates suspicious/malicious activity.
        """
        # Determine if event is significant enough to warrant an incident or join one
        is_attack = detection and detection.predicted_class not in ["BENIGN", "Other"]
        is_anom = anomaly and anomaly.is_anomalous
        is_high_sev = event.severity.upper() in ["HIGH", "CRITICAL"]
        is_suspicious_type = event.event_type.lower() in [
            "brute_force", "failed_login", "port_scan", "privilege_escalation",
            "sensitive_file_access", "unusual_outbound_traffic", "suspicious_process",
            "lateral_movement", "reconnaissance", "sql_injection", "web_attack"
        ]

        if not (is_attack or is_anom or is_high_sev or is_suspicious_type):
            return None

        # Look for open incidents within the correlation window
        window_minutes = settings.CORRELATION_WINDOW_MINUTES
        window_start = (event.timestamp or datetime.datetime.utcnow()) - datetime.timedelta(minutes=window_minutes)
        window_end = (event.timestamp or datetime.datetime.utcnow()) + datetime.timedelta(minutes=window_minutes)

        ACTIVE_STATES = [
            "NEW", "INVESTIGATING", "Investigating",
            "AWAITING_USER_VERIFICATION", "USER_CONFIRMED", "USER_DENIED",
            "CONTAINMENT_PENDING", "CONTAINED", "Contained"
        ]
        candidate_query = db.query(Incident).filter(
            Incident.status.in_(ACTIVE_STATES),
            Incident.updated_at >= window_start,
            Incident.created_at <= window_end,
        )

        matched_incident: Optional[Incident] = None

        # Try matching by primary pivots: Source IP, User, or Hostname
        for inc in candidate_query.order_by(desc(Incident.updated_at)).all():
            ip_match = inc.source_ip and inc.source_ip == event.source_ip
            user_match = inc.user and event.user and inc.user == event.user
            host_match = inc.hostname and event.hostname and inc.hostname == event.hostname

            if ip_match or user_match or host_match:
                matched_incident = inc
                break

        if matched_incident:
            # Check if this event is already attached
            existing_link = db.query(IncidentEvent).filter(
                IncidentEvent.incident_id == matched_incident.id,
                IncidentEvent.event_id == event.id
            ).first()

            if not existing_link:
                link = IncidentEvent(
                    incident_id=matched_incident.id,
                    event_id=event.id,
                    created_at=datetime.datetime.utcnow()
                )
                db.add(link)
                db.flush()

                # Update incident pivots if empty
                if not matched_incident.source_ip and event.source_ip:
                    matched_incident.source_ip = event.source_ip
                if not matched_incident.user and event.user:
                    matched_incident.user = event.user
                if not matched_incident.hostname and event.hostname:
                    matched_incident.hostname = event.hostname

                # Re-calculate incident risk with updated events
                all_events = (
                    db.query(SecurityEvent)
                    .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
                    .filter(IncidentEvent.incident_id == matched_incident.id)
                    .all()
                )

                # Recompute MITRE techniques
                mitre_technique_ids = MitreService.map_event_to_techniques(
                    event.event_type,
                    detection.predicted_class if detection else None
                )
                MitreService.link_incident_techniques(db, matched_incident.id, mitre_technique_ids)

                mitre_count = db.query(IncidentMitreMapping).filter(
                    IncidentMitreMapping.incident_id == matched_incident.id
                ).count()

                event_risk_dicts = []
                for ev in all_events:
                    ev_det = db.query(Detection).filter(Detection.event_id == ev.id).first()
                    ev_anom = db.query(Anomaly).filter(Anomaly.event_id == ev.id).first()
                    risk_info = risk_engine.calculate_event_risk(
                        {"severity": ev.severity, "user": ev.user, "hostname": ev.hostname},
                        {"predicted_class": ev_det.predicted_class, "confidence": ev_det.confidence} if ev_det else None,
                        {"anomaly_score": ev_anom.anomaly_score} if ev_anom else None,
                    )
                    event_risk_dicts.append(risk_info)

                inc_risk = risk_engine.calculate_incident_risk(event_risk_dicts, mitre_count=mitre_count)
                matched_incident.risk_score = inc_risk["risk_score"]
                matched_incident.severity = inc_risk["severity"]
                matched_incident.updated_at = datetime.datetime.utcnow()

                # Upgrade title if multi-stage progression is identified
                event_types = {e.event_type.lower() for e in all_events}
                if {"brute_force", "privilege_escalation"}.issubset(event_types):
                    matched_incident.title = f"Multi-Stage Compromise: Brute Force to Privilege Escalation on {matched_incident.hostname or 'Host'}"
                elif {"failed_login", "privilege_escalation", "sensitive_file_access"}.issubset(event_types):
                    matched_incident.title = f"Account Takeover and Sensitive Data Exfiltration on {matched_incident.hostname or 'Host'}"
                elif len(all_events) > 3:
                    matched_incident.title = f"Coordinated Attack Campaign from {matched_incident.source_ip}"

                db.commit()
            return matched_incident

        else:
            # Create a brand new incident
            new_id = CorrelationEngine._generate_incident_id(db)
            event_title = event.event_type.replace("_", " ").title()
            if detection and detection.predicted_class != "BENIGN":
                event_title = f"{detection.predicted_class} Attack"

            single_risk = risk_engine.calculate_event_risk(
                {"severity": event.severity, "user": event.user, "hostname": event.hostname},
                {"predicted_class": detection.predicted_class, "confidence": detection.confidence} if detection else None,
                {"anomaly_score": anomaly.anomaly_score} if anomaly else None,
            )

            new_incident = Incident(
                incident_id=new_id,
                title=f"{event_title} Detected on {event.hostname or event.destination_ip}",
                severity=single_risk["severity"],
                risk_score=single_risk["risk_score"],
                status="Investigating",
                source_ip=event.source_ip,
                user=event.user,
                hostname=event.hostname,
                summary=f"Automated incident generated following suspicious activity ({event.event_type}) detected from {event.source_ip} targeting {event.destination_ip}:{event.destination_port or ''}.",
                created_at=event.timestamp or datetime.datetime.utcnow(),
                updated_at=event.timestamp or datetime.datetime.utcnow(),
            )
            db.add(new_incident)
            db.flush()

            # Attach event
            link = IncidentEvent(
                incident_id=new_incident.id,
                event_id=event.id,
                created_at=datetime.datetime.utcnow()
            )
            db.add(link)

            # Map MITRE techniques
            mitre_tids = MitreService.map_event_to_techniques(
                event.event_type,
                detection.predicted_class if detection else None
            )
            MitreService.link_incident_techniques(db, new_incident.id, mitre_tids)

            # Audit log
            audit = AuditLog(
                incident_id=new_incident.id,
                action="INCIDENT_CREATED",
                actor="correlation_engine",
                details={
                    "trigger_event_id": event.id,
                    "event_type": event.event_type,
                    "initial_risk": single_risk["risk_score"],
                    "severity": single_risk["severity"]
                }
            )
            db.add(audit)
            db.commit()
            return new_incident

    @staticmethod
    def get_incident_timeline(db: Session, incident_id: int) -> List[Dict[str, Any]]:
        """
        Build an ordered chronological attack timeline for an incident.
        """
        records = (
            db.query(SecurityEvent, Detection, Anomaly)
            .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
            .outerjoin(Detection, Detection.event_id == SecurityEvent.id)
            .outerjoin(Anomaly, Anomaly.event_id == SecurityEvent.id)
            .filter(IncidentEvent.incident_id == incident_id)
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        timeline = []
        for event, detection, anomaly in records:
            desc = CorrelationEngine._format_event_description(event, detection, anomaly)
            timeline.append({
                "timestamp": event.timestamp,
                "event_id": event.id,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "user": event.user,
                "hostname": event.hostname,
                "prediction": detection.predicted_class if detection else None,
                "anomaly_score": anomaly.anomaly_score if anomaly else None,
                "is_anomalous": anomaly.is_anomalous if anomaly else False,
                "description": desc,
            })
        return timeline


correlation_engine = CorrelationEngine()
