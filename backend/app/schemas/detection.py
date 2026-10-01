from datetime import datetime
from pydantic import BaseModel, Field


class DetectionResponse(BaseModel):
    id: int
    event_id: int
    model_name: str
    predicted_class: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    created_at: datetime
    model_config = {"from_attributes": True}
