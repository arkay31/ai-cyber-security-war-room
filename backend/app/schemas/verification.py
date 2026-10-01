from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, Field


class VerificationCreateRequest(BaseModel):
    user_id: Optional[str] = Field(None, description="Username to challenge")
    activity_summary: Optional[str] = Field(None, description="Safe user-facing description of the suspicious activity")
    delivery_method: str = Field("DEMO_PORTAL", description="DEMO_PORTAL, SMS_LINK, or AUTH_APP")
    expires_in_minutes: int = Field(15, ge=1, le=120)


class VerificationResponseItem(BaseModel):
    id: int
    response: str
    authenticated: bool
    verification_method: str
    responded_at: datetime
    client_ip: Optional[str] = None

    model_config = {"from_attributes": True}


class VerificationRequestResponse(BaseModel):
    id: int
    incident_id: int
    user_id: str
    challenge_id: str
    status: str
    activity_summary: str
    requested_by: str
    delivery_method: str
    verification_url: str
    created_at: datetime
    expires_at: datetime
    responses: List[VerificationResponseItem] = []

    model_config = {"from_attributes": True}


class PublicChallengeDetailResponse(BaseModel):
    challenge_id: str
    incident_id: str
    user_id: str
    status: str
    activity_summary: str
    created_at: datetime
    expires_at: datetime
    is_expired: bool
    question: str = "Did you perform this activity?"


class UserVerifySubmitRequest(BaseModel):
    response: str = Field(..., description="'CONFIRMED' (Yes, it was me) or 'DENIED' (No, I did not do this)")
    verification_method: Optional[str] = Field("DEMO_VERIFICATION", description="Authentication challenge method")
    auth_pin: Optional[str] = Field(None, description="Optional 4-digit PIN for demo authentication step")
