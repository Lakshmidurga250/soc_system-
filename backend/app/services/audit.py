from sqlalchemy.orm import Session
from ..models import AuditLog

def audit(db: Session, action: str, resource: str, user_id: str | None = None, result: str = "SUCCESS", **metadata) -> AuditLog:
    entry = AuditLog(user_id=user_id, action=action, resource=resource, result=result, metadata_json=metadata)
    db.add(entry); db.flush()
    return entry
