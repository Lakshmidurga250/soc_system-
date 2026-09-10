"""Response Actions, Mitigation Playbooks & Safe Simulation Endpoints."""
from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...models import ResponseAction, ApprovalRequest
from ...schemas.domain import ResponseRequest
from ...services.audit import audit
from ...services.response_simulator import response_simulator, SUPPORTED_ACTIONS
from ..deps import current_user, require_roles

router = APIRouter(prefix="/response", tags=["Response Center"])

class SimulateActionRequest(BaseModel):
    action_type: str = Field(pattern="^(ISOLATE_HOST|BLOCK_IP|DISABLE_USER|REVOKE_CREDENTIALS|FORENSIC_SNAPSHOT)$")
    target: str = Field(min_length=2, max_length=256)
    incident_id: Optional[str] = None
    reason: Optional[str] = None

@router.get("/templates")
def list_supported_simulation_templates(user = Depends(current_user)):
    """List all available safe response actions and containment descriptions."""
    return {"templates": SUPPORTED_ACTIONS}

@router.get("/history")
def list_response_history(db: Session = Depends(get_db), user = Depends(current_user)):
    """List all executed containment actions with simulated status."""
    actions = db.scalars(select(ResponseAction).order_by(desc(ResponseAction.created_at)).limit(50)).all()
    return {
        "items": [
            {
                "id": a.id,
                "incident_id": a.incident_id,
                "action_type": a.action_type,
                "mode": a.mode,
                "target": a.target,
                "status": a.status,
                "payload": a.payload,
                "executed_at": a.created_at.isoformat() if a.created_at else None,
                "executed_by": a.executed_by,
            }
            for a in actions
        ]
    }

@router.post("/simulate")
def execute_simulated_containment(
    payload: SimulateActionRequest,
    db: Session = Depends(get_db),
    user = Depends(require_roles("ADMIN", "SOC_ANALYST"))
):
    """Execute a non-destructive containment action in safe simulation mode."""
    res = response_simulator.execute_simulated_action(
        db=db,
        action_type=payload.action_type,
        target=payload.target,
        analyst_id=user.id,
        incident_id=payload.incident_id,
        reason=payload.reason
    )
    return res

@router.post("/actions")
def request_response_action(
    payload: ResponseRequest,
    db: Session = Depends(get_db),
    user = Depends(require_roles("ADMIN", "SOC_ANALYST"))
):
    action = ResponseAction(
        incident_id=payload.incident_id,
        action_type=payload.action_type,
        target=payload.payload.get("target", "system"),
        mode=payload.mode,
        payload=payload.payload,
        status="PENDING" if payload.mode == "APPROVAL_REQUIRED" else "EXECUTED",
        executed_by=user.id if payload.mode != "APPROVAL_REQUIRED" else None,
    )
    db.add(action)
    db.flush()
    result = {"id": action.id, "status": action.status}
    if payload.mode == "APPROVAL_REQUIRED":
        req = ApprovalRequest(response_action_id=action.id, reason=payload.reason)
        db.add(req)
        db.flush()
        result["approval_id"] = req.id
    audit(db, "RESPONSE_ACTION_DISPATCHED", f"action:{action.id}", user.id, action_type=payload.action_type, mode=payload.mode)
    db.commit()
    return result
