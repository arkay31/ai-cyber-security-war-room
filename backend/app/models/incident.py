import datetime
from sqlalchemy import Column, Integer, String, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(String(32), unique=True, index=True, nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 to 100.0
    status = Column(String(32), nullable=False, default="Investigating")  # Investigating, Contained, Resolved, False Positive
    source_ip = Column(String(64), index=True, nullable=True)
    user = Column(String(128), index=True, nullable=True)
    hostname = Column(String(128), index=True, nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow, nullable=False)

    # Relationships
    incident_events = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    mitre_mappings = relationship("IncidentMitreMapping", back_populates="incident", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="incident", cascade="all, delete-orphan")
    verification_requests = relationship(
        "VerificationRequest",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="desc(VerificationRequest.created_at)"
    )
    response_actions = relationship("ResponseAction", back_populates="incident", cascade="all, delete-orphan")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="incident_events")
    event = relationship("SecurityEvent", back_populates="incident_links")
