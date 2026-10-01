from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from backend.app.schemas.security_event import SecurityEventResponse
from backend.app.schemas.detection import DetectionResponse
from backend.app.schemas.anomaly import AnomalyResponse
from backend.app.schemas.mitre import MitreTechniqueResponse


class IncidentBase(BaseModel):
    incident_id: str
    title: str
    severity: str = "MEDIUM"
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    status: str = "Investigating"
    source_ip: Optional[str] = None
    user: Optional[str] = None
    hostname: Optional[str] = None
    summary: Optional[str] = None


class IncidentCreate(IncidentBase):
    event_ids: Optional[List[int]] = None
    mitre_technique_ids: Optional[List[str]] = None


class IncidentResponse(IncidentBase):
    id: int
    created_at: datetime
    updated_at: datetime
    event_count: Optional[int] = 0
    mitre_techniques: Optional[List[str]] = []
    model_config = {"from_attributes": True}


class EnrichedEventResponse(SecurityEventResponse):
    detections: List[DetectionResponse] = []
    anomalies: List[AnomalyResponse] = []


class TimelineItem(BaseModel):
    timestamp: datetime
    event_id: int
    event_type: str
    severity: str
    source_ip: str
    destination_ip: str
    user: Optional[str] = None
    hostname: Optional[str] = None
    prediction: Optional[str] = None
    anomaly_score: Optional[float] = None
    is_anomalous: Optional[bool] = False
    description: str


class IncidentDetailResponse(IncidentResponse):
    events: List[EnrichedEventResponse] = []
    timeline: List[TimelineItem] = []
    mitre_details: List[MitreTechniqueResponse] = []
    evidence: Dict[str, Any] = {}
    audit_logs: List[Dict[str, Any]] = []
    verification_requests: List[Dict[str, Any]] = []
    response_actions: List[Dict[str, Any]] = []


class IncidentDecisionRequest(BaseModel):
    status: str = Field(..., description="Target incident status according to state machine")
    action_notes: Optional[str] = Field(None, description="Analyst rationale or action notes")
    actor: Optional[str] = Field("analyst", description="Name/role of analyst")


class IncidentInvestigateResponse(BaseModel):
    incident_id: str
    status: str
    analysis_mode: str = Field("LLM_RAG", description="Analysis engine mode: LLM_RAG, LLM, or RULE_BASED")
    llm_status: Optional[str] = Field(None, description="LLM, LLM_RAG, or LLM_UNAVAILABLE")
    llm_model: Optional[str] = None
    confidence: float = 0.85
    incident_summary: str
    observed_evidence: List[str] = []
    likely_attack_pattern: Optional[str] = None
    mitre_techniques: List[Dict[str, Any]] = []
    root_cause_hypothesis: Optional[str] = None
    investigation_steps: List[str] = []
    prioritized_recommendations: List[str] = []
    evidence_references: List[Dict[str, Any]] = []
    analyst_warning: Optional[str] = None
    
    # Backward compatibility fields
    investigation_summary: Optional[str] = None
    recommended_steps: Optional[List[str]] = None
    recommended_actions: Optional[List[str]] = None
    evidence_gathered: Optional[Dict[str, Any]] = None
