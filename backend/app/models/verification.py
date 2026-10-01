import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.app.database import Base


class VerificationRequest(Base):
    """
    Human-in-the-loop user verification challenge requested by SOC Analyst.
    """
    __tablename__ = "verification_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(128), index=True, nullable=False)
    challenge_id = Column(String(64), unique=True, index=True, nullable=False)
    status = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, CONFIRMED, DENIED, EXPIRED
    activity_summary = Column(Text, nullable=False)
    requested_by = Column(String(128), default="analyst", nullable=False)
    delivery_method = Column(String(64), default="DEMO_PORTAL", nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)

    # Relationships
    incident = relationship("Incident", back_populates="verification_requests")
    responses = relationship("VerificationResponse", back_populates="request", cascade="all, delete-orphan")


class VerificationResponse(Base):
    """
    Record of user response to an authentication / activity challenge.
    """
    __tablename__ = "verification_responses"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    verification_request_id = Column(Integer, ForeignKey("verification_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    response = Column(String(32), nullable=False)  # CONFIRMED, DENIED
    authenticated = Column(Boolean, default=True, nullable=False)
    verification_method = Column(String(64), default="DEMO_VERIFICATION", nullable=False)
    client_ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    responded_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    # Relationships
    request = relationship("VerificationRequest", back_populates="responses")
