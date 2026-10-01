from typing import List, Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping
from backend.app.services.mitre_service import MitreService

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])


@router.get("/techniques")
def get_techniques(db: Session = Depends(get_db)):
    # Auto-seed if empty
    if db.query(MitreTechnique).count() == 0:
        MitreService.seed_techniques(db)

    techs = db.query(MitreTechnique).order_by(MitreTechnique.tactic, MitreTechnique.technique_id).all()

    results = []
    for t in techs:
        inc_count = db.query(IncidentMitreMapping).filter(IncidentMitreMapping.technique_id == t.id).count()
        results.append({
            "id": t.id,
            "technique_id": t.technique_id,
            "name": t.name,
            "description": t.description,
            "tactic": t.tactic,
            "external_id": t.external_id,
            "incident_count": inc_count,
            "created_at": t.created_at.isoformat()
        })
    return results


@router.post("/seed")
def seed_mitre(db: Session = Depends(get_db)):
    count = MitreService.seed_techniques(db)
    return {"status": "success", "seeded_techniques": count}
