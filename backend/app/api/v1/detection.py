"""Detection Rule Engine and Sandbox Testing endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import DetectionRule
from ...schemas.domain import RuleCreate, RuleTestRequest
from ...services.audit import audit
from ..deps import current_user, require_roles

router = APIRouter(prefix="/detection", tags=["Detection Rules"])

@router.get("/rules")
def get_rules(db: Session = Depends(get_db), user = Depends(current_user)):
    return {
        "items": [
            {
                "id": x.id,
                "name": x.name,
                "description": x.description,
                "rule_type": x.rule_type,
                "category": x.category,
                "config": x.config,
                "severity": x.severity,
                "enabled": x.enabled,
                "execution_count": x.execution_count,
                "match_count": x.match_count,
            }
            for x in db.scalars(select(DetectionRule)).all()
        ]
    }

@router.post("/rules")
def create_detection_rule(payload: RuleCreate, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    item = DetectionRule(**payload.model_dump())
    db.add(item)
    audit(db, "RULE_CREATED", f"rule:{item.id}", user.id, rule_name=item.name)
    db.commit()
    return {"id": item.id, "name": item.name}

@router.patch("/rules/{rule_id}")
def update_detection_rule(rule_id: str, payload: RuleCreate, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    rule = db.get(DetectionRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    for k, v in payload.model_dump().items():
        setattr(rule, k, v)
    audit(db, "RULE_UPDATED", f"rule:{rule.id}", user.id, enabled=rule.enabled)
    db.commit()
    return {"id": rule.id, "enabled": rule.enabled}

@router.post("/rules/test")
def test_rule_sandbox(payload: RuleTestRequest, user = Depends(current_user)):
    cfg = payload.rule_config
    evt = payload.event_payload
    matches = True
    reasons = []

    if "event_type" in cfg and cfg["event_type"] != evt.get("event_type"):
        matches = False
        reasons.append(f"event_type mismatch: expected {cfg['event_type']}, got {evt.get('event_type')}")
    if "status" in cfg and cfg["status"] != evt.get("status"):
        matches = False
        reasons.append(f"status mismatch: expected {cfg['status']}, got {evt.get('status')}")
    if "severity" in cfg and cfg["severity"] != evt.get("severity"):
        matches = False
        reasons.append(f"severity mismatch: expected {cfg['severity']}, got {evt.get('severity')}")

    return {
        "matches": matches,
        "evaluated_rule": cfg,
        "reasons": reasons if not matches else ["All criteria matched candidate payload."],
    }
