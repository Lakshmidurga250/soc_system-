"""Autonomous Investigation Engine for SentinelAI."""
from datetime import timezone
from typing import Dict, Any, List
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ..models import Incident, Alert, SecurityEvent, Investigation
from ..services.audit import audit
from ..optimization.investigation_optimizer import investigation_optimizer

class InvestigationEngine:
    def execute_investigation(self, db: Session, incident_id: str, investigator_id: str | None = None) -> Investigation:
        incident = db.get(Incident, incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")

        alerts = [db.get(Alert, a_id) for a_id in (incident.alert_ids or []) if db.get(Alert, a_id)]
        root_event_ids = {eid for a in alerts for eid in (a.event_ids or [])}
        root_events = [db.get(SecurityEvent, eid) for eid in root_event_ids if db.get(SecurityEvent, eid)]

        affected_ips = {e.source_ip for e in root_events if e.source_ip}
        affected_users = {e.username for e in root_events if e.username}
        affected_hosts = {e.hostname for e in root_events if e.hostname}

        # Query surrounding candidate telemetry (last 1000 events)
        candidates = db.scalars(select(SecurityEvent).order_by(desc(SecurityEvent.timestamp)).limit(1000)).all()
        ranked = []
        for e in candidates:
            score = 0
            if e.source_ip and e.source_ip in affected_ips:
                score += 35
            if e.username and e.username in affected_users:
                score += 30
            if e.hostname and e.hostname in affected_hosts:
                score += 25
            if e.id in root_event_ids:
                score += 20
            score += {"CRITICAL": 20, "HIGH": 15, "MEDIUM": 8}.get(e.severity, 2)

            if score >= 15:
                ranked.append((score, e))

        ranked.sort(key=lambda x: x[0], reverse=True)
        selected = ranked[:100]

        evidence_list = [
            {
                "event_id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "source_ip": e.source_ip,
                "username": e.username,
                "hostname": e.hostname,
                "relevance_score": s,
            }
            for s, e in selected
        ]

        timeline_entries = [
            {
                "at": e.timestamp.isoformat(),
                "event_id": e.id,
                "description": f"{e.event_type.upper()} on {e.hostname or 'host'} by user '{e.username or 'system'}' from {e.source_ip or 'internal'} (status: {e.status})",
            }
            for s, e in selected
        ]

        # Optimize investigation path
        optimized_plan = investigation_optimizer.optimize_investigation_plan(
            incident_id=incident.id,
            affected_entities={
                "source_ips": list(affected_ips),
                "usernames": list(affected_users),
                "hostnames": list(affected_hosts),
            }
        )

        inv = Investigation(
            incident_id=incident.id,
            status="COMPLETED",
            summary=f"Autonomous forensic scan correlated {len(selected)} evidence items across {len(affected_ips)} IPs, {len(affected_users)} identities, and {len(affected_hosts)} hosts.",
            evidence=evidence_list,
            timeline=timeline_entries,
            statistics={
                "candidate_events_evaluated": len(candidates),
                "selected_evidence_count": len(selected),
                "reduction_ratio": round(1.0 - (len(selected) / max(1, len(candidates))), 3),
                "correlated_ips": list(affected_ips),
                "correlated_users": list(affected_users),
                "correlated_hosts": list(affected_hosts),
                "optimization_plan": optimized_plan,
            },
        )
        db.add(inv)
        incident.status = "INVESTIGATING"
        db.flush()
        audit(db, "INVESTIGATION_COMPLETED", f"incident:{incident.id}", investigator_id, evidence_count=len(selected))
        return inv

investigation_engine = InvestigationEngine()
