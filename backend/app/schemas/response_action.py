from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


class ResponseActionCreateRequest(BaseModel):
    action: str = Field(..., description="BLOCK_SOURCE_IP, ISOLATE_HOST, REVOKE_USER_SESSION, FORENSIC_SNAPSHOT, DISABLE_ACCOUNT")
    reason: str = Field(..., description="Analyst justification and intent for containment/mitigation")
    analyst_id: Optional[str] = Field("lead_analyst", description="ID or name of SOC analyst proposing the action")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Target parameters, e.g. target_ip, target_host, target_user")


class ResponseActionExecuteRequest(BaseModel):
    analyst_id: Optional[str] = Field("lead_analyst", description="Analyst approving/executing the action")
    notes: Optional[str] = Field(None, description="Execution or approval notes")


class ResponseActionResponse(BaseModel):
    id: int
    incident_id: int
    analyst_id: str
    action: str
    reason: str
    status: str
    parameters: Optional[Dict[str, Any]] = {}
    execution_log: Optional[str] = None
    created_at: datetime
    approved_at: Optional[datetime] = None
    executed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
