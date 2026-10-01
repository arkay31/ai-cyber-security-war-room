import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(64), nullable=False)  # e.g., STATUS_CHANGE, COMMENT, MITRE_MAPPED, AI_INVESTIGATED
    actor = Column(String(128), default="analyst", nullable=False)
    details = Column(JSON, default=dict, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="audit_logs")
