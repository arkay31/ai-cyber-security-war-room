import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class ResponseAction(Base):
    """
    Controlled response actions triggered for an incident (e.g. host quarantine, firewall block).
    Initially executed in safe SIMULATED mode for the academic environment.
    """
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id = Column(String(128), default="lead_analyst", nullable=False)
    action = Column(String(64), nullable=False)  # BLOCK_SOURCE_IP, ISOLATE_HOST, REVOKE_USER_SESSION, FORENSIC_SNAPSHOT, DISABLE_ACCOUNT
    reason = Column(Text, nullable=False)
    status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, APPROVED, EXECUTED, REJECTED, FAILED
    parameters = Column(JSON, default=dict, nullable=True)  # e.g., {"target_ip": "...", "target_host": "..."}
    execution_log = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)

    # Relationships
    incident = relationship("Incident", back_populates="response_actions")
