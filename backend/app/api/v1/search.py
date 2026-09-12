"""Global Grouped Search Controller for SentinelAI SOC Platform."""
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ...core.database import get_db
from ...models import (
    Alert, Incident, SecurityEvent, Asset, ThreatIndicator, User
)
from ..deps import current_user

router = APIRouter(prefix="/search", tags=["Global Search"])

@router.get("", response_model=Dict[str, Any])
def global_search(
    q: str = Query(..., min_length=1, description="Search query string"),
    limit_per_category: int = Query(5, ge=1, le=50),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
) -> Dict[str, Any]:
    """Execute unified fuzzy search across alerts, incidents, telemetry events, assets, indicators, and users."""
    search_term = f"%{q.strip()}%"
    
    # 1. Search Alerts
    alerts = db.query(Alert).filter(
        or_(
            Alert.title.ilike(search_term),
            Alert.description.ilike(search_term),
            Alert.source.ilike(search_term),
            Alert.detection_method.ilike(search_term),
            Alert.status.ilike(search_term)
        )
    ).order_by(Alert.created_at.desc()).limit(limit_per_category).all()
    
    # 2. Search Incidents
    incidents = db.query(Incident).filter(
        or_(
            Incident.title.ilike(search_term),
            Incident.description.ilike(search_term),
            Incident.severity.ilike(search_term),
            Incident.status.ilike(search_term),
            Incident.root_cause.ilike(search_term)
        )
    ).order_by(Incident.created_at.desc()).limit(limit_per_category).all()
    
    # 3. Search Security Events
    events = db.query(SecurityEvent).filter(
        or_(
            SecurityEvent.source_ip.ilike(search_term),
            SecurityEvent.destination_ip.ilike(search_term),
            SecurityEvent.username.ilike(search_term),
            SecurityEvent.hostname.ilike(search_term),
            SecurityEvent.event_type.ilike(search_term),
            SecurityEvent.category.ilike(search_term),
            SecurityEvent.resource.ilike(search_term)
        )
    ).order_by(SecurityEvent.timestamp.desc()).limit(limit_per_category).all()
    
    # 4. Search Assets
    assets = db.query(Asset).filter(
        or_(
            Asset.hostname.ilike(search_term),
            Asset.ip_address.ilike(search_term),
            Asset.asset_type.ilike(search_term),
            Asset.operating_system.ilike(search_term),
            Asset.owner.ilike(search_term)
        )
    ).limit(limit_per_category).all()
    
    # 5. Search Threat Indicators
    indicators = db.query(ThreatIndicator).filter(
        or_(
            ThreatIndicator.indicator.ilike(search_term),
            ThreatIndicator.indicator_type.ilike(search_term),
            ThreatIndicator.description.ilike(search_term)
        )
    ).limit(limit_per_category).all()
    
    # 6. Search Users (Admin / Analyst view)
    users_matched = []
    if user.role in ["ADMIN", "SOC_ANALYST"]:
        matched_users = db.query(User).filter(
            or_(
                User.full_name.ilike(search_term),
                User.username.ilike(search_term),
                User.email.ilike(search_term),
                User.role.ilike(search_term)
            )
        ).limit(limit_per_category).all()
        users_matched = [
            {
                "id": u.id,
                "full_name": u.full_name,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "is_active": u.is_active
            }
            for u in matched_users
        ]

    total_matches = (
        len(alerts) + len(incidents) + len(events) +
        len(assets) + len(indicators) + len(users_matched)
    )

    return {
        "query": q,
        "total_matches": total_matches,
        "categories": {
            "alerts": [
                {
                    "id": a.id,
                    "title": a.title,
                    "severity": a.severity,
                    "risk_score": a.risk_score,
                    "status": a.status,
                    "detection_method": a.detection_method,
                    "created_at": a.created_at.isoformat() if a.created_at else None
                }
                for a in alerts
            ],
            "incidents": [
                {
                    "id": inc.id,
                    "title": inc.title,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                    "status": inc.status,
                    "created_at": inc.created_at.isoformat() if inc.created_at else None
                }
                for inc in incidents
            ],
            "events": [
                {
                    "id": ev.id,
                    "event_id": ev.event_id,
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                    "source_ip": ev.source_ip,
                    "destination_ip": ev.destination_ip,
                    "username": ev.username,
                    "hostname": ev.hostname,
                    "event_type": ev.event_type,
                    "severity": ev.severity
                }
                for ev in events
            ],
            "assets": [
                {
                    "id": ast.id,
                    "hostname": ast.hostname,
                    "ip_address": ast.ip_address,
                    "asset_type": ast.asset_type,
                    "criticality": ast.criticality,
                    "status": ast.status
                }
                for ast in assets
            ],
            "threat_indicators": [
                {
                    "id": ind.id,
                    "indicator": ind.indicator,
                    "indicator_type": ind.indicator_type,
                    "risk_level": ind.risk_level,
                    "status": ind.status
                }
                for ind in indicators
            ],
            "users": users_matched
        }
    }
