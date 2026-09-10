"""Multi-Factor Transparent Risk Calculator endpoint."""
from fastapi import APIRouter, Depends, Query
from ...engines.risk_engine import risk_engine
from ..deps import current_user

router = APIRouter(prefix="/risk", tags=["Risk Analytics"])

@router.get("/calculate")
def calculate_risk(
    severity: str = Query(default="HIGH"),
    confidence: float = Query(default=0.85, ge=0.0, le=1.0),
    behavior_deviation: float = Query(default=0.5, ge=0.0, le=1.0),
    threat_intel_match: bool = Query(default=False),
    user = Depends(current_user)
):
    return risk_engine.calculate_risk(
        severity=severity,
        confidence=confidence,
        behavior_deviation=behavior_deviation,
        threat_intel_match=threat_intel_match
    )
