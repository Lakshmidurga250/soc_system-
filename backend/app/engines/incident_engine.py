"""Incident Lifecycle & Aggregation Engine for SentinelAI."""
from typing import List, Dict, Any
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ..models import Alert, Incident
from ..services.audit import audit

class IncidentEngine:
    def create_incident_from_alert(self, db: Session, alert_id: str, creator_id: str | None = None) -> Incident:
        alert = db.get(Alert, alert_id)
        if not alert:
            raise ValueError(f"Alert {alert_id} not found")

        incident = Incident(
            title=f"Incident: {alert.title}",
            description=alert.description,
            severity=alert.severity,
            risk_score=alert.risk_score,
            confidence=alert.confidence_score,
            status="OPEN",
            assigned_to=creator_id,
            alert_ids=[alert.id],
        )
        db.add(incident)
        alert.status = "ESCALATED"
        db.flush()
        audit(db, "INCIDENT_CREATED", f"incident:{incident.id}", creator_id, alert_id=alert.id)
        return incident

    def update_incident(self, db: Session, incident_id: str, updates: Dict[str, Any], user_id: str | None = None) -> Incident:
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        for k, v in updates.items():
            if v is not None:
                setattr(incident, k, v)
        audit(db, "INCIDENT_UPDATED", f"incident:{incident.id}", user_id, status=incident.status)
        return incident

incident_engine = IncidentEngine()
