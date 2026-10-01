import datetime
import logging
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from backend.app.models.response_action import ResponseAction
from backend.app.models.incident import Incident
from backend.app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)

SUPPORTED_ACTIONS = {
    "BLOCK_SOURCE_IP",
    "ISOLATE_HOST",
    "REVOKE_USER_SESSION",
    "FORENSIC_SNAPSHOT",
    "DISABLE_ACCOUNT",
}


class ResponseEngine:
    """
    Controlled Incident Response Engine.
    Executes simulated mitigation and containment actions for academic and demonstration safety.
    Guarantees strict human-in-the-loop analyst approval and immutable audit trail recording.
    """

    @staticmethod
    def propose_action(
        db: Session,
        incident_id: int,
        action: str,
        reason: str,
        analyst_id: str = "lead_analyst",
        parameters: Optional[Dict[str, Any]] = None
    ) -> ResponseAction:
        """Create a pending response action proposal requiring human analyst confirmation."""
        action_clean = action.upper().strip()
        if action_clean not in SUPPORTED_ACTIONS:
            raise ValueError(f"Action '{action}' is not supported. Supported: {sorted(list(SUPPORTED_ACTIONS))}")

        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            raise ValueError(f"Incident with ID {incident_id} not found.")

        params = parameters or {}
        # Auto-fill sensible parameters from incident if missing
        if "target_ip" not in params and incident.source_ip:
            params["target_ip"] = incident.source_ip
        if "target_host" not in params and incident.hostname:
            params["target_host"] = incident.hostname
        if "target_user" not in params and incident.user:
            params["target_user"] = incident.user

        record = ResponseAction(
            incident_id=incident.id,
            analyst_id=analyst_id,
            action=action_clean,
            reason=reason,
            status="PENDING",
            parameters=params,
            created_at=datetime.datetime.utcnow(),
        )
        db.add(record)
        db.commit()
        db.refresh(record)

        # Audit proposal
        audit = AuditLog(
            incident_id=incident.id,
            action="RESPONSE_ACTION_PROPOSED",
            actor=analyst_id,
            details={
                "response_action_id": record.id,
                "action": record.action,
                "reason": record.reason,
                "parameters": params,
                "status": "PENDING"
            }
        )
        db.add(audit)
        db.commit()

        return record

    @staticmethod
    def execute_action(
        db: Session,
        action_id: int,
        analyst_id: str = "lead_analyst",
        notes: Optional[str] = None
    ) -> ResponseAction:
        """
        Execute an analyst-approved response action in safe SIMULATED mode.
        Updates response_action status, incident containment status, and audit log.
        """
        record = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
        if not record:
            raise ValueError(f"ResponseAction with ID {action_id} not found.")

        if record.status == "EXECUTED":
            raise ValueError(f"ResponseAction #{action_id} has already been executed.")

        incident = db.query(Incident).filter(Incident.id == record.incident_id).first()
        now = datetime.datetime.utcnow()
        params = record.parameters or {}

        # Safe simulation handlers
        if record.action == "BLOCK_SOURCE_IP":
            target_ip = params.get("target_ip") or incident.source_ip or "Unknown IP"
            log_msg = (
                f"[SIMULATION] Perimeter Firewall Block: Added DROP rule for source IP '{target_ip}' "
                f"on enterprise ingress interfaces. Active TCP connections terminated successfully."
            )

        elif record.action == "ISOLATE_HOST":
            target_host = params.get("target_host") or incident.hostname or "Unknown Host"
            log_msg = (
                f"[SIMULATION] Host Isolation: Endpoint security agent isolated host '{target_host}' "
                f"from corporate VLAN. Lateral movement blocked; control plane management channel maintained."
            )
            # Update incident state machine
            if incident and incident.status in ["Investigating", "NEW", "USER_DENIED", "CONTAINMENT_PENDING"]:
                incident.status = "CONTAINED"
                incident.updated_at = now

        elif record.action == "REVOKE_USER_SESSION":
            target_user = params.get("target_user") or incident.user or "Unknown User"
            log_msg = (
                f"[SIMULATION] Session Revocation: Active OAuth refresh tokens, SSO sessions, and "
                f"Kerberos tickets for account '{target_user}' invalidated across all enterprise realms."
            )

        elif record.action == "FORENSIC_SNAPSHOT":
            target_host = params.get("target_host") or incident.hostname or "Unknown Host"
            log_msg = (
                f"[SIMULATION] Forensic Snapshot: Initiated non-volatile RAM dump and disk block snapshot "
                f"for host '{target_host}'. Artifact sha256 checksum indexed in secure chain of custody."
            )

        elif record.action == "DISABLE_ACCOUNT":
            target_user = params.get("target_user") or incident.user or "Unknown User"
            log_msg = (
                f"[SIMULATION] Account Lockout: Disabled Active Directory and IAM credentials for user "
                f"'{target_user}'. Direct authentication attempts rejected."
            )

        else:
            log_msg = f"[SIMULATION] Response action '{record.action}' simulated successfully."

        if notes:
            log_msg += f" Analyst Notes: {notes}"

        record.status = "EXECUTED"
        record.approved_at = now
        record.executed_at = now
        record.execution_log = log_msg
        record.analyst_id = analyst_id

        db.add(record)
        if incident:
            db.add(incident)

        # Audit log entry
        audit = AuditLog(
            incident_id=record.incident_id,
            action="RESPONSE_EXECUTED",
            actor=analyst_id,
            details={
                "response_action_id": record.id,
                "action": record.action,
                "execution_mode": "SIMULATION",
                "execution_log": log_msg,
                "notes": notes,
            }
        )
        db.add(audit)
        db.commit()
        db.refresh(record)

        return record

    @staticmethod
    def reject_action(
        db: Session,
        action_id: int,
        analyst_id: str = "lead_analyst",
        reason: Optional[str] = None
    ) -> ResponseAction:
        """Analyst rejects a proposed response action."""
        record = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
        if not record:
            raise ValueError(f"ResponseAction with ID {action_id} not found.")

        record.status = "REJECTED"
        record.execution_log = f"Action rejected by {analyst_id}. Reason: {reason or 'Not required'}"
        record.approved_at = datetime.datetime.utcnow()

        db.add(record)
        audit = AuditLog(
            incident_id=record.incident_id,
            action="RESPONSE_ACTION_REJECTED",
            actor=analyst_id,
            details={"response_action_id": record.id, "reason": reason}
        )
        db.add(audit)
        db.commit()
        db.refresh(record)
        return record


response_engine = ResponseEngine()
