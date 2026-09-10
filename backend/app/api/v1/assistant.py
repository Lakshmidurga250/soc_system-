"""Local Investigation Assistant & MITRE ATT&CK Endpoints."""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...engines.assistant_engine import assistant_engine
from ...intelligence.mitre_mapper import mitre_mapper
from ..deps import current_user

router = APIRouter(prefix="/assistant", tags=["Investigation Assistant"])

class InvestigationQuery(BaseModel):
    incident_id: str
    question: str = Field(min_length=3, max_length=500)

@router.post("/query")
def ask_investigation_assistant(payload: InvestigationQuery, db: Session = Depends(get_db), user = Depends(current_user)):
    """Ask deterministic SOC Investigation Assistant questions regarding any incident."""
    res = assistant_engine.query_incident_investigation(
        db=db,
        incident_id=payload.incident_id,
        question=payload.question
    )
    return res

@router.get("/mitre/matrix")
def get_mitre_attack_matrix(user = Depends(current_user)):
    """Retrieve the complete local MITRE ATT&CK taxonomy and technique reference mappings."""
    return {"matrix": mitre_mapper.get_full_matrix()}

@router.get("/mitre/category/{category}")
def get_mitre_category_detail(category: str, user = Depends(current_user)):
    """Retrieve specific MITRE ATT&CK technique details for a threat category."""
    return mitre_mapper.map_category(category)
