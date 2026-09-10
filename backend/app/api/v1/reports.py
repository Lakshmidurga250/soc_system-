"""Forensic & Executive PDF Report Generator endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...models import Incident, Alert, SecurityEvent, Investigation
from ...services.reporting import generate_incident_pdf, generate_soc_executive_pdf
from ..deps import current_user

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/incidents/{incident_id}/pdf")
def export_incident_report_pdf(incident_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = [db.get(Alert, a_id) for a_id in (incident.alert_ids or []) if db.get(Alert, a_id)]
    inv = db.scalar(select(Investigation).where(Investigation.incident_id == incident.id))
    pdf_bytes = generate_incident_pdf(incident, alerts, inv)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident_{incident.id[:8]}_forensic.pdf"'}
    )

@router.get("/executive-summary/pdf")
def export_executive_summary_pdf(db: Session = Depends(get_db), user = Depends(current_user)):
    count = lambda q: db.scalar(q) or 0
    kpis = {
        "total_events": count(select(func.count()).select_from(SecurityEvent)),
        "active_alerts": count(select(func.count()).select_from(Alert).where(Alert.status.not_in(["RESOLVED", "FALSE_POSITIVE", "CLOSED"]))),
        "open_incidents": count(select(func.count()).select_from(Incident).where(Incident.status == "OPEN")),
        "critical_incidents": count(select(func.count()).select_from(Incident).where(Incident.severity == "CRITICAL")),
        "anomalies_detected": count(select(func.count()).select_from(Alert).where(Alert.detection_method.in_(["ML", "ML_ANOMALY"]))),
        "investigations_running": count(select(func.count()).select_from(Investigation).where(Investigation.status == "RUNNING")),
    }
    by_sev = dict(db.execute(select(Alert.severity, func.count()).group_by(Alert.severity)).all())
    pdf_bytes = generate_soc_executive_pdf(kpis, by_sev)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="sentinelai_soc_executive_summary.pdf"'}
    )
