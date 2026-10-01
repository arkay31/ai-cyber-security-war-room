from datetime import datetime
from typing import Optional
from pydantic import BaseModel


class MitreTechniqueBase(BaseModel):
    technique_id: str
    name: str
    description: str
    tactic: str
    external_id: Optional[str] = None


class MitreTechniqueCreate(MitreTechniqueBase):
    pass


class MitreTechniqueResponse(MitreTechniqueBase):
    id: int
    created_at: datetime
    model_config = {"from_attributes": True}


class IncidentMitreMappingResponse(BaseModel):
    id: int
    incident_id: int
    technique: MitreTechniqueResponse
    confidence: Optional[float] = 1.0
    created_at: datetime
    model_config = {"from_attributes": True}
