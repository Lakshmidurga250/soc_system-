"""Behavioral Analytics & Historical Baseline Profiler for SentinelAI."""
from datetime import timedelta
from typing import Dict, Any
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import SecurityEvent

class BehaviorEngine:
    def get_entity_profile(self, db: Session, entity_type: str, entity_value: str) -> Dict[str, Any]:
        """Calculates statistical baseline profile across historical telemetry."""
        stmt = select(SecurityEvent)
        if entity_type.lower() == "user":
            stmt = stmt.where(SecurityEvent.username == entity_value)
        elif entity_type.lower() == "host":
            stmt = stmt.where(SecurityEvent.hostname == entity_value)
        elif entity_type.lower() == "ip":
            stmt = stmt.where(SecurityEvent.source_ip == entity_value)
        else:
            return {"entity": entity_value, "total_events": 0, "status": "UNKNOWN_ENTITY"}

        events = db.scalars(stmt.limit(1000)).all()
        if not events:
            return {
                "entity": entity_value,
                "entity_type": entity_type,
                "total_events": 0,
                "status": "NO_HISTORICAL_ACTIVITY",
                "failure_rate": 0.0,
                "common_event_types": [],
                "active_hours": [],
            }

        failures = sum(1 for e in events if e.status == "FAILURE")
        failure_rate = round(failures / len(events), 3)

        event_type_counts = {}
        hour_counts = {}
        for e in events:
            event_type_counts[e.event_type] = event_type_counts.get(e.event_type, 0) + 1
            hour_counts[e.timestamp.hour] = hour_counts.get(e.timestamp.hour, 0) + 1

        top_events = sorted(event_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        common_hours = sorted(hour_counts.keys())

        return {
            "entity": entity_value,
            "entity_type": entity_type,
            "total_events": len(events),
            "failure_rate": failure_rate,
            "common_event_types": [{"type": k, "count": v} for k, v in top_events],
            "active_hours": common_hours,
            "status": "ELEVATED_RISK" if failure_rate > 0.4 else "NORMAL",
            "behavioral_summary": f"Historical profile analyzed across {len(events)} events with a {failure_rate*100:.1f}% failure rate.",
        }

behavior_engine = BehaviorEngine()
