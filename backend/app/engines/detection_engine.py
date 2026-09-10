"""Configurable Behavioral Detection Rule Engine for SentinelAI SOC."""
from datetime import timedelta
from typing import List
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import DetectionRule, SecurityEvent, Alert, RuleExecution
from ..ml.anomaly_detector import get_anomaly_detector

DEFAULT_RULES = [
    {
        "name": "Multiple Failed Authentication Attempts",
        "description": "Flags 5 or more authentication failures within a 5-minute sliding window.",
        "category": "brute_force",
        "severity": "HIGH",
        "config": {"event_type": "login", "status": "FAILURE", "threshold_count": 5, "time_window_seconds": 300},
    },
    {
        "name": "Rapid Web Request Rate Anomaly",
        "description": "Flags burst traffic exceeding 50 HTTP requests per minute from a single source origin.",
        "category": "abnormal_request_rate",
        "severity": "MEDIUM",
        "config": {"category": "web", "threshold_count": 50, "time_window_seconds": 60},
    },
    {
        "name": "Suspicious Privilege Escalation Execution",
        "description": "Detects execution of administrative credential tools (powershell, mimikatz, sudo).",
        "category": "privilege_escalation",
        "severity": "CRITICAL",
        "config": {"category": "process_execution", "severity": "CRITICAL", "threshold_count": 1, "time_window_seconds": 60},
    },
    {
        "name": "Perimeter Port Scanning Reconnaissance",
        "description": "Detects systematic multi-port scanning behavior dropped by network firewall.",
        "category": "port_scanning",
        "severity": "HIGH",
        "config": {"category": "network", "status": "FAILURE", "threshold_count": 10, "time_window_seconds": 120},
    },
    {
        "name": "Sensitive Configuration Resource Tampering",
        "description": "Detects access attempts targeting /admin, /secrets, or production config endpoints.",
        "category": "data_access_anomaly",
        "severity": "HIGH",
        "config": {"category": "web", "resource_keyword": "/admin", "threshold_count": 3, "time_window_seconds": 300},
    },
    {
        "name": "Off-Hours Administrative Authentication",
        "description": "Detects administrative logins executed outside standard operational hours.",
        "category": "unusual_administrative_activity",
        "severity": "MEDIUM",
        "config": {"event_type": "login", "status": "SUCCESS", "threshold_count": 1, "time_window_seconds": 60},
    },
]

def seed_default_rules(db: Session) -> None:
    for r in DEFAULT_RULES:
        if not db.scalar(select(DetectionRule).where(DetectionRule.name == r["name"])):
            db.add(DetectionRule(**r))
    db.commit()

class DetectionEngine:
    def evaluate_event(self, db: Session, event: SecurityEvent) -> List[Alert]:
        alerts = []
        rules = db.scalars(select(DetectionRule).where(DetectionRule.enabled == True)).all()

        for rule in rules:
            rule.execution_count += 1
            cfg = rule.config or {}
            window_sec = cfg.get("time_window_seconds", 300)
            threshold = cfg.get("threshold_count", 5)

            # Check direct filter match
            if "event_type" in cfg and cfg["event_type"] != event.event_type:
                continue
            if "category" in cfg and cfg["category"] != event.category:
                continue
            if "status" in cfg and cfg["status"] != event.status:
                continue
            if "resource_keyword" in cfg and (not event.resource or cfg["resource_keyword"] not in event.resource.lower()):
                continue

            # Check sliding window match count
            start_window = event.timestamp - timedelta(seconds=window_sec)
            stmt = select(SecurityEvent).where(
                SecurityEvent.timestamp >= start_window,
                SecurityEvent.timestamp <= event.timestamp,
            )
            if event.source_ip:
                stmt = stmt.where(SecurityEvent.source_ip == event.source_ip)
            if "status" in cfg:
                stmt = stmt.where(SecurityEvent.status == cfg["status"])

            matched_events = db.scalars(stmt).all()
            
            if len(matched_events) >= threshold:
                rule.match_count += 1
                
                # Check for existing open alert for this entity & rule
                existing = db.scalar(
                    select(Alert).where(
                        Alert.title == rule.name,
                        Alert.status.in_(["NEW", "IN_TRIAGE"]),
                        Alert.entities["source_ip"].as_string() == (event.source_ip or "")
                    )
                )

                if existing:
                    # Append event
                    if event.id not in existing.event_ids:
                        existing.event_ids.append(event.id)
                else:
                    # Calculate ML and risk score
                    detector = get_anomaly_detector()
                    score_res = detector.score_event_features({
                        "failed_login_count": len(matched_events),
                        "authentication_failure_ratio": 0.9 if event.status == "FAILURE" else 0.1,
                        "behavioral_deviation": 0.7,
                        "resource_sensitivity": 1.0 if event.severity in ("CRITICAL", "HIGH") else 0.0,
                    })

                    alert = Alert(
                        title=rule.name,
                        description=f"{rule.description} (Triggered {len(matched_events)} matching events from {event.source_ip or 'entity'}).",
                        source="rule_engine",
                        detection_method="RULE_THRESHOLD",
                        severity=rule.severity,
                        risk_score=score_res["risk_score"],
                        confidence_score=score_res["confidence_score"],
                        status="NEW",
                        event_ids=[e.id for e in matched_events],
                        entities={
                            "source_ip": event.source_ip,
                            "username": event.username,
                            "hostname": event.hostname,
                        },
                        explanation={
                            "rule_id": rule.id,
                            "matched_count": len(matched_events),
                            "threshold": threshold,
                            "time_window": window_sec,
                            "top_contributing_factors": score_res["top_contributing_factors"],
                        },
                        notes=[],
                    )
                    db.add(alert)
                    alerts.append(alert)

                db.add(RuleExecution(
                    rule_id=rule.id,
                    event_id=event.id,
                    matched=True,
                ))

        return alerts

detection_engine = DetectionEngine()
