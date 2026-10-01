import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True, nullable=False)
    source_ip = Column(String(64), index=True, nullable=False)
    destination_ip = Column(String(64), index=True, nullable=False)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="TCP", nullable=False)
    user = Column(String(128), index=True, nullable=True)
    hostname = Column(String(128), index=True, nullable=True)
    event_type = Column(String(64), index=True, nullable=False)
    severity = Column(String(32), default="medium", nullable=False)
    raw_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    detections = relationship("Detection", back_populates="event", cascade="all, delete-orphan")
    anomalies = relationship("Anomaly", back_populates="event", cascade="all, delete-orphan")
    incident_links = relationship("IncidentEvent", back_populates="event", cascade="all, delete-orphan")
