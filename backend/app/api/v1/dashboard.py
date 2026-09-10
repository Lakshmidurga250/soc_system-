"""SOC Dashboard Overview and Telemetry KPIs."""
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import SecurityEvent, Alert, Incident, Investigation
from ..deps import current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("")
def get_dashboard_metrics(db: Session = Depends(get_db), user = Depends(current_user)):
    count = lambda q: db.scalar(q) or 0
    total_events = count(select(func.count()).select_from(SecurityEvent))
    active_alerts = count(select(func.count()).select_from(Alert).where(Alert.status.not_in(["RESOLVED", "FALSE_POSITIVE", "CLOSED"])))
    open_incidents = count(select(func.count()).select_from(Incident).where(Incident.status == "OPEN"))
    crit_incidents = count(select(func.count()).select_from(Incident).where(Incident.severity == "CRITICAL"))
    ml_anomalies = count(select(func.count()).select_from(Alert).where(Alert.detection_method.in_(["ML", "ML_ANOMALY"])))
    running_invs = count(select(func.count()).select_from(Investigation).where(Investigation.status == "RUNNING"))

    by_sev = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        by_sev.setdefault(s, 0)

    by_status = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())

    recent = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "risk_score": a.risk_score,
            "status": a.status,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in db.scalars(select(Alert).order_by(desc(Alert.created_at)).limit(10)).all()
    ]

    return {
        "kpis": {
            "total_events": total_events,
            "active_alerts": active_alerts,
            "open_incidents": open_incidents,
            "critical_incidents": crit_incidents,
            "anomalies_detected": ml_anomalies,
            "investigations_running": running_invs,
        },
        "alerts_by_severity": by_sev,
        "incidents_by_status": by_status,
        "recent_alerts": recent,
    }
