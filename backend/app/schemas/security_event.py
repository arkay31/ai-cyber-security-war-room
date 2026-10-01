from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class SecurityEventBase(BaseModel):
    timestamp: Optional[datetime] = Field(default_factory=datetime.utcnow, description="Event occurrence timestamp")
    source_ip: str = Field(..., description="Source IP address")
    destination_ip: str = Field(..., description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: str = Field(default="TCP", description="Network protocol (e.g. TCP, UDP, ICMP, SSH, HTTP)")
    user: Optional[str] = Field(None, description="User associated with event")
    hostname: Optional[str] = Field(None, description="Target or source hostname")
    event_type: str = Field(..., description="Security event type e.g. failed_login, port_scan, brute_force")
    severity: str = Field(default="medium", description="Severity level: low, medium, high, critical")
    raw_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Raw metadata or network flow features")


class SecurityEventCreate(SecurityEventBase):
    pass


class SecurityEventBulkCreate(BaseModel):
    events: List[SecurityEventCreate]


class SecurityEventResponse(SecurityEventBase):
    id: int
    created_at: datetime
    model_config = {"from_attributes": True}
