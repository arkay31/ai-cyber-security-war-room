from datetime import datetime
from pydantic import BaseModel


class AnomalyResponse(BaseModel):
    id: int
    event_id: int
    anomaly_score: float
    is_anomalous: bool
    model_name: str
    created_at: datetime
    model_config = {"from_attributes": True}
