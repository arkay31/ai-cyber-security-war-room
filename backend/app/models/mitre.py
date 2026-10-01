import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    technique_id = Column(String(32), unique=True, index=True, nullable=False)  # e.g., T1110, T1046
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    tactic = Column(String(128), nullable=False, index=True)  # e.g., Credential Access, Discovery
    external_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    incident_mappings = relationship("IncidentMitreMapping", back_populates="technique", cascade="all, delete-orphan")


class IncidentMitreMapping(Base):
    __tablename__ = "incident_mitre_mappings"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id = Column(Integer, ForeignKey("mitre_techniques.id", ondelete="CASCADE"), nullable=False, index=True)
    confidence = Column(Float, nullable=True, default=1.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="mitre_mappings")
    technique = relationship("MitreTechnique", back_populates="incident_mappings")
