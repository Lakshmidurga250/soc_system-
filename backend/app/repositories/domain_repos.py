"""Specialized Domain Repositories for SentinelAI."""
from typing import Sequence
from sqlalchemy import select, desc, func
from sqlalchemy.orm import Session
from ..models import (
    User, SecurityEvent, Alert, Incident, Investigation,
    ThreatIndicator, DetectionRule, ResponseAction, ApprovalRequest, AuditLog
)
from .base import BaseRepository

class UserRepository(BaseRepository[User]):
    def __init__(self, db: Session):
        super().__init__(User, db)

    def get_by_email(self, email: str) -> User | None:
        return self.db.scalar(select(User).where(User.email == email))

class EventRepository(BaseRepository[SecurityEvent]):
    def __init__(self, db: Session):
        super().__init__(SecurityEvent, db)

    def search_events(self, query: str | None = None, severity: str | None = None, page: int = 1, page_size: int = 50) -> tuple[Sequence[SecurityEvent], int]:
        stmt = select(SecurityEvent)
        count_stmt = select(func.count()).select_from(SecurityEvent)

        if severity and severity.upper() != "ALL":
            stmt = stmt.where(SecurityEvent.severity == severity.upper())
            count_stmt = count_stmt.where(SecurityEvent.severity == severity.upper())

        if query:
            p = f"%{query}%"
            cond = (
                SecurityEvent.raw_message.ilike(p)
                | SecurityEvent.source_ip.ilike(p)
                | SecurityEvent.username.ilike(p)
                | SecurityEvent.event_type.ilike(p)
            )
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)

        total = self.db.scalar(count_stmt) or 0
        items = self.db.scalars(
            stmt.order_by(desc(SecurityEvent.timestamp))
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        return items, total

class AlertRepository(BaseRepository[Alert]):
    def __init__(self, db: Session):
        super().__init__(Alert, db)

    def list_by_status(self, status: str | None = None, limit: int = 50) -> Sequence[Alert]:
        stmt = select(Alert)
        if status and status.upper() != "ALL":
            stmt = stmt.where(Alert.status == status.upper())
        return self.db.scalars(stmt.order_by(desc(Alert.created_at)).limit(limit)).all()

class IncidentRepository(BaseRepository[Incident]):
    def __init__(self, db: Session):
        super().__init__(Incident, db)

    def list_open_incidents(self) -> Sequence[Incident]:
        return self.db.scalars(select(Incident).order_by(desc(Incident.created_at))).all()

class ThreatRepository(BaseRepository[ThreatIndicator]):
    def __init__(self, db: Session):
        super().__init__(ThreatIndicator, db)

    def find_match(self, value: str) -> ThreatIndicator | None:
        return self.db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator == value, ThreatIndicator.status == "ACTIVE"))

class RuleRepository(BaseRepository[DetectionRule]):
    def __init__(self, db: Session):
        super().__init__(DetectionRule, db)

    def list_enabled(self) -> Sequence[DetectionRule]:
        return self.db.scalars(select(DetectionRule).where(DetectionRule.enabled == True)).all()

class ResponseRepository(BaseRepository[ResponseAction]):
    def __init__(self, db: Session):
        super().__init__(ResponseAction, db)

class ApprovalRepository(BaseRepository[ApprovalRequest]):
    def __init__(self, db: Session):
        super().__init__(ApprovalRequest, db)

    def list_pending(self) -> Sequence[ApprovalRequest]:
        return self.db.scalars(select(ApprovalRequest).where(ApprovalRequest.status == "PENDING")).all()

class AuditRepository(BaseRepository[AuditLog]):
    def __init__(self, db: Session):
        super().__init__(AuditLog, db)

    def list_recent(self, limit: int = 250) -> Sequence[AuditLog]:
        return self.db.scalars(select(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit)).all()
