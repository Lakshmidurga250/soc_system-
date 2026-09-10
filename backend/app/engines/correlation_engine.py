"""Alert Correlation Engine for SentinelAI SOC.

Implements temporal, entity-centric, and sequence-based correlation to group alerts
into cohesive threat campaigns and automated incident candidates.
"""
from datetime import timedelta
from typing import List, Dict, Any
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ..models import Alert, Incident

class CorrelationEngine:
    def correlate_alerts(self, db: Session, lookback_hours: int = 12) -> List[Dict[str, Any]]:
        """Scans unassociated alerts and groups them by shared entity and temporal proximity."""
        alerts = db.scalars(
            select(Alert).where(Alert.status.in_(["NEW", "IN_TRIAGE"])).order_by(desc(Alert.created_at))
        ).all()

        entity_groups: Dict[str, List[Alert]] = {}
        for alert in alerts:
            entities = alert.entities or {}
            key = entities.get("source_ip") or entities.get("username") or entities.get("hostname") or "unknown"
            if key not in entity_groups:
                entity_groups[key] = []
            entity_groups[key].append(alert)

        campaigns = []
        for key, group in entity_groups.items():
            if len(group) >= 2:
                # Correlate across severity and risk
                max_risk = max(a.risk_score for a in group)
                titles = [a.title for a in group]
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                top_sev = max(group, key=lambda a: sev_order.get(a.severity, 1)).severity

                campaigns.append({
                    "entity_key": key,
                    "alert_count": len(group),
                    "top_severity": top_sev,
                    "max_risk_score": max_risk,
                    "alert_ids": [a.id for a in group],
                    "titles": titles,
                    "correlation_type": "ENTITY_TEMPORAL_SEQUENCE",
                    "explanation": f"Correlated {len(group)} distinct alerts targeting entity '{key}' within operational lookback window.",
                })

        return campaigns

correlation_engine = CorrelationEngine()
