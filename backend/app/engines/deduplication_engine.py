"""Intelligent Alert Deduplication & Noise Suppression Engine."""
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from sqlalchemy import select, and_
from sqlalchemy.orm import Session
from ..models import Alert, SecurityEvent

class DeduplicationEngine:
    """Groups repetitive, high-frequency security events and alerts into deduplicated clusters."""

    def __init__(self, time_window_minutes: int = 15):
        self.time_window_minutes = time_window_minutes

    def generate_event_signature(self, event: SecurityEvent) -> str:
        """Create a deterministic hash signature based on entity, attack type, and target resource."""
        raw_key = f"{event.source_ip}:{event.destination_ip}:{event.event_type}:{event.resource or ''}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]

    def find_or_create_deduplicated_alert(
        self,
        db: Session,
        event: SecurityEvent,
        rule_name: str,
        severity: str,
        risk_score: float,
        confidence_score: float,
        explanation: Dict[str, Any]
    ) -> Tuple[Alert, bool]:
        """Find an existing active alert matching the signature within the temporal window, or create a new alert."""
        sig = self.generate_event_signature(event)
        window_start = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=self.time_window_minutes)

        # Look for open/investigating alerts with same source/destination and title
        stmt = select(Alert).where(
            and_(
                Alert.title == rule_name,
                Alert.status.in_(["NEW", "INVESTIGATING"]),
                Alert.created_at >= window_start
            )
        )
        existing_alerts = db.scalars(stmt).all()
        
        for candidate in existing_alerts:
            # Check entity match
            ent = candidate.entities or {}
            if ent.get("source_ip") == event.source_ip or ent.get("username") == event.username:
                # Merge event into existing alert
                ev_ids = list(candidate.event_ids or [])
                if event.id not in ev_ids:
                    ev_ids.append(event.id)
                    candidate.event_ids = ev_ids
                    # Update frequency & risk
                    candidate.risk_score = min(100.0, candidate.risk_score + 1.5)
                    candidate.confidence_score = min(1.0, candidate.confidence_score + 0.02)
                    candidate.description = f"Aggregated {len(ev_ids)} correlated occurrences of {rule_name} from {event.source_ip or event.username}"
                    db.commit()
                    db.refresh(candidate)
                    return candidate, False

        # Create new deduplicated alert
        new_alert = Alert(
            title=rule_name,
            description=f"Initial detection of {rule_name} from {event.source_ip or event.username}",
            severity=severity,
            risk_score=risk_score,
            confidence_score=confidence_score,
            status="NEW",
            source=event.source or "DETECTION_ENGINE",
            detection_method="BEHAVIORAL_RULE",
            entities={
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "username": event.username,
                "hostname": event.hostname,
                "signature": sig,
            },
            event_ids=[event.id],
            explanation=explanation,
            notes=[{"author": "SYSTEM_DEDUPLICATION", "note": "Initial alert instance created", "at": datetime.now(timezone.utc).isoformat()}],
        )
        db.add(new_alert)
        db.commit()
        db.refresh(new_alert)
        return new_alert, True

    def calculate_deduplication_metrics(self, db: Session) -> Dict[str, Any]:
        """Calculate SOC alert noise reduction metrics."""
        total_events = db.query(SecurityEvent).count()
        total_alerts = db.query(Alert).count()
        noise_reduction_pct = 0.0
        if total_events > 0:
            noise_reduction_pct = round(max(0.0, (1.0 - (total_alerts / max(1, total_events))) * 100.0), 2)

        return {
            "total_raw_events": total_events,
            "total_deduplicated_alerts": total_alerts,
            "noise_reduction_percentage": noise_reduction_pct,
            "deduplication_ratio": f"{round(total_events / max(1, total_alerts), 1)}:1" if total_alerts else "1:1",
        }

deduplication_engine = DeduplicationEngine()
