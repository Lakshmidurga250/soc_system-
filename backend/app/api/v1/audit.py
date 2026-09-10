"""Forensic Audit Trail & Activity Logging endpoints."""
from fastapi import APIRouter, Depends
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import AuditLog
from ..deps import require_roles

router = APIRouter(prefix="/audit", tags=["Audit Logs"])

@router.get("")
def list_audit_trail(db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    items = db.scalars(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(250)).all()
    return {
        "items": [
            {
                "id": x.id,
                "action": x.action,
                "resource": x.resource,
                "result": x.result,
                "timestamp": x.timestamp.isoformat() if x.timestamp else None,
                "metadata": x.metadata_json,
                "user_id": x.user_id,
            }
            for x in items
        ]
    }
