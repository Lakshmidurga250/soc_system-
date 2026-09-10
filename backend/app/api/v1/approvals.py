"""Dual-Custody Approval Queue and Decision endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import ApprovalRequest, ResponseAction
from ...schemas.domain import ApprovalDecision
from ...services.audit import audit
from ..deps import current_user, require_roles

router = APIRouter(prefix="/approvals", tags=["Approval Queue"])

@router.get("")
def list_pending_approvals(db: Session = Depends(get_db), user = Depends(current_user)):
    return {
        "items": [
            {
                "id": x.id,
                "response_action_id": x.response_action_id,
                "reason": x.reason,
                "status": x.status,
                "created_at": x.created_at.isoformat() if x.created_at else None,
                "action": db.get(ResponseAction, x.response_action_id),
            }
            for x in db.scalars(select(ApprovalRequest).where(ApprovalRequest.status == "PENDING")).all()
        ]
    }

@router.post("/{approval_id}/decision")
def decide_approval(approval_id: str, payload: ApprovalDecision, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    req = db.get(ApprovalRequest, approval_id)
    if not req or req.status != "PENDING":
        raise HTTPException(status_code=404, detail="Pending approval request not found")

    req.status = "APPROVED" if payload.approved else "REJECTED"
    req.decision_by = user.id
    req.decision_note = payload.note

    action = db.get(ResponseAction, req.response_action_id)
    if action:
        action.status = "EXECUTED" if payload.approved else "REJECTED"
        action.executed_by = user.id if payload.approved else None

    audit(db, "APPROVAL_DECIDED", f"approval:{req.id}", user.id, decision=req.status, note=payload.note)
    db.commit()
    return {"status": req.status}
