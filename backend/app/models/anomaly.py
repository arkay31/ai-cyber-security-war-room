import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class Anomaly(Base):
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(Integer, ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False, index=True)
    anomaly_score = Column(Float, nullable=False)
    is_anomalous = Column(Boolean, default=False, nullable=False)
    model_name = Column(String(64), nullable=False, default="isolation_forest")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    event = relationship("SecurityEvent", back_populates="anomalies")
