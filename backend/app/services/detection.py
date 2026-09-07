from collections import Counter
from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import Alert, DetectionRule, SecurityEvent, ThreatIndicator
from .risk import score

def seed_rules(db: Session) -> None:
    defaults = [("Repeated authentication failures", "Detects failed logins from one IP within a time window.", {"event_type": "login", "status": "FAILURE", "threshold": 5, "window_minutes": 15}, "HIGH"), ("Sensitive resource access", "Flags access to sensitive resources.", {"resource_keywords": ["/admin", "/payroll", "/secrets"]}, "HIGH"), ("Request burst", "Detects excessive events by a source.", {"threshold": 20, "window_minutes": 1}, "MEDIUM")]
    for name, description, config, severity in defaults:
        if not db.scalar(select(DetectionRule).where(DetectionRule.name == name)):
            db.add(DetectionRule(name=name, description=description, config=config, severity=severity))

def run_rules(db: Session, event: SecurityEvent) -> list[Alert]:
    alerts=[]
    for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True))).all():
        rule.execution_count += 1; cfg=rule.config; matches=[]
        if rule.name == "Repeated authentication failures" and event.source_ip and event.status == "FAILURE":
            since = event.timestamp - timedelta(minutes=cfg.get("window_minutes",15))
            matches = db.scalars(select(SecurityEvent).where(SecurityEvent.source_ip == event.source_ip, SecurityEvent.status == "FAILURE", SecurityEvent.timestamp >= since)).all()
            if len(matches) < cfg.get("threshold",5): matches=[]
        elif rule.name == "Sensitive resource access" and event.resource:
            matches = [event] if any(k in event.resource.lower() for k in cfg.get("resource_keywords", [])) else []
        elif rule.name == "Request burst" and event.source_ip:
            since=event.timestamp-timedelta(minutes=cfg.get("window_minutes",1)); matches=db.scalars(select(SecurityEvent).where(SecurityEvent.source_ip==event.source_ip,SecurityEvent.timestamp>=since)).all()
            if len(matches)<cfg.get("threshold",20): matches=[]
        if matches:
            intel = bool(event.source_ip and db.scalar(select(ThreatIndicator).where(ThreatIndicator.indicator == event.source_ip, ThreatIndicator.status == "ACTIVE")))
            details=score(severity=rule.severity,count=len(matches),indicator=intel)
            explanation={"rule": rule.name, "indicators": [f"{len(matches)} related events", f"source IP: {event.source_ip}"] + (["matched local threat indicator"] if intel else [])}
            alert=Alert(title=rule.name, description=rule.description, source="rule_engine", detection_method="RULE", severity=details["severity"], risk_score=details["risk_score"], confidence_score=details["confidence_score"], event_ids=[x.id for x in matches], entities={"source_ip":event.source_ip,"username":event.username}, explanation=explanation)
            db.add(alert); rule.match_count+=1; alerts.append(alert)
    return alerts
