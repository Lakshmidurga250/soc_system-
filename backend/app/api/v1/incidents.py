"""Incident Case Management, Attack Timelines, Playbooks & Optimization Endpoints."""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from ...core.database import get_db
from ...models import Incident, Alert, SecurityEvent, Investigation
from ...schemas.domain import IncidentUpdate
from ...engines.incident_engine import incident_engine
from ...engines.investigation_engine import investigation_engine
from ...optimization.investigation_optimizer import investigation_optimizer
from ...ml.playbook_generator import generate_incident_playbook
from ...repositories import IncidentRepository
from ..deps import current_user, require_roles

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("")
def list_incidents(db: Session = Depends(get_db), user = Depends(current_user)):
    repo = IncidentRepository(db)
    items = repo.list_open_incidents()
    return {
        "items": [
            {
                "id": x.id,
                "title": x.title,
                "description": x.description,
                "severity": x.severity,
                "risk_score": x.risk_score,
                "confidence": x.confidence,
                "status": x.status,
                "assigned_to": x.assigned_to,
                "alert_ids": x.alert_ids,
                "root_cause": x.root_cause,
                "created_at": x.created_at.isoformat() if x.created_at else None,
            }
            for x in items
        ]
    }

@router.get("/{incident_id}")
def get_incident_detail(incident_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    # Fetch correlated alerts
    alerts = []
    for a_id in (incident.alert_ids or []):
        al = db.get(Alert, a_id)
        if al:
            alerts.append({
                "id": al.id,
                "title": al.title,
                "severity": al.severity,
                "risk_score": al.risk_score,
                "status": al.status,
                "source": al.source,
                "created_at": al.created_at.isoformat() if al.created_at else None,
            })

    # Adaptive pipeline optimization data
    opt_data = investigation_optimizer.schedule_adaptive_pipeline(
        severity=incident.severity,
        risk_score=incident.risk_score
    )

    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "confidence": incident.confidence,
        "status": incident.status,
        "assigned_to": incident.assigned_to,
        "alert_ids": incident.alert_ids,
        "correlated_alerts": alerts,
        "root_cause": incident.root_cause,
        "resolution": incident.resolution,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "optimization_efficiency": opt_data,
    }

@router.get("/{incident_id}/timeline")
def get_incident_attack_timeline(incident_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    """Retrieve visual chronological attack progression timeline."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    alerts = [db.get(Alert, a_id) for a_id in (incident.alert_ids or []) if db.get(Alert, a_id)]
    
    timeline_steps = []
    # Step 1: Ingestion
    timeline_steps.append({
        "phase": "1. Telemetry Ingestion",
        "title": "Raw Telemetry Ingested",
        "description": f"Initial log events captured from perimeter firewall and authentication servers.",
        "timestamp": incident.created_at.isoformat() if incident.created_at else None,
        "status": "COMPLETED",
        "severity": "INFORMATIONAL"
    })
    
    # Step 2: Detection & Correlation
    for idx, al in enumerate(alerts[:5]):
        timeline_steps.append({
            "phase": f"2.{idx+1} Alert Triggered",
            "title": al.title,
            "description": al.description or f"Behavioral detection triggered with risk score {al.risk_score}/100.",
            "timestamp": al.created_at.isoformat() if al.created_at else None,
            "status": "TRIGGERED",
            "severity": al.severity
        })

    # Step 3: Correlation & Escalation
    timeline_steps.append({
        "phase": "3. Incident Correlation",
        "title": "Correlated Attack Chain Formed",
        "description": f"Incident aggregated {len(alerts)} alerts into MITRE ATT&CK progression chain.",
        "timestamp": incident.created_at.isoformat() if incident.created_at else None,
        "status": "AGGREGATED",
        "severity": incident.severity
    })

    # Step 4: AI Playbook & Containment
    timeline_steps.append({
        "phase": "4. Autonomous Mitigation",
        "title": "Remediation Playbook Generated",
        "description": "4-Phase mitigation playbook created; pending safe simulation approval.",
        "timestamp": incident.created_at.isoformat() if incident.created_at else None,
        "status": "ACTIONABLE",
        "severity": "MEDIUM"
    })

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "timeline": timeline_steps
    }

@router.post("/from-alert/{alert_id}")
def escalate_alert_to_incident(alert_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    try:
        inc = incident_engine.create_incident_from_alert(db, alert_id=alert_id, creator_id=user.id)
        db.commit()
        return {"id": inc.id, "status": inc.status}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.patch("/{incident_id}")
def patch_incident(incident_id: str, payload: IncidentUpdate, db: Session = Depends(get_db), user = Depends(require_roles("ADMIN", "SOC_ANALYST"))):
    try:
        inc = incident_engine.update_incident(db, incident_id=incident_id, updates=payload.model_dump(exclude_unset=True), user_id=user.id)
        db.commit()
        return {"id": inc.id, "status": inc.status}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.post("/{incident_id}/investigate")
def run_autonomous_investigation(incident_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    try:
        inv = investigation_engine.execute_investigation(db, incident_id=incident_id, investigator_id=user.id)
        db.commit()
        return {
            "id": inv.id,
            "incident_id": inv.incident_id,
            "status": inv.status,
            "summary": inv.summary,
            "evidence": inv.evidence,
            "timeline": inv.timeline,
            "statistics": inv.statistics,
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

@router.get("/{incident_id}/playbook")
def get_mitigation_playbook(incident_id: str, db: Session = Depends(get_db), user = Depends(current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = [db.get(Alert, a_id) for a_id in (incident.alert_ids or []) if db.get(Alert, a_id)]
    event_ids = [eid for a in alerts for eid in (a.event_ids or [])]
    events = [db.get(SecurityEvent, eid) for eid in event_ids if db.get(SecurityEvent, eid)]
    return generate_incident_playbook(incident, alerts, events)
