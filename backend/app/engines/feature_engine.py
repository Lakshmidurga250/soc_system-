"""Real-Time & Historical Feature Engineering Pipeline for SentinelAI."""
from datetime import datetime, timezone, timedelta
import math
from typing import Dict
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..models import EventFeature, SecurityEvent, ThreatIndicator

SENSITIVE_RESOURCES = (
    "/admin", "/secrets", "/payroll", "/production", "/config",
    "/etc/shadow", "/etc/passwd", "cmd.exe", "powershell.exe", "mimikatz"
)

def calculate_entropy(values: list) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def _to_naive(dt):
    if dt is not None and getattr(dt, "tzinfo", None) is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt

class FeatureEngine:
    def extract_features(self, db: Session, event: SecurityEvent) -> EventFeature:
        evt_ts = _to_naive(event.timestamp)
        lookback_start = evt_ts - timedelta(minutes=60)
        
        # Query recent events for entity
        stmt = select(SecurityEvent).where(SecurityEvent.timestamp >= lookback_start)
        if event.source_ip or event.username:
            stmt = stmt.where(
                (SecurityEvent.source_ip == event.source_ip) | (SecurityEvent.username == event.username)
            )
            related_events = db.scalars(stmt).all()
        else:
            related_events = []

        failed_count = sum(1 for e in related_events if e.status == "FAILURE")
        success_count = sum(1 for e in related_events if e.status == "SUCCESS")
        
        minute_start = evt_ts - timedelta(minutes=1)
        velocity_rpm = sum(1 for e in related_events if _to_naive(e.timestamp) >= minute_start)

        unique_ips = len({e.source_ip for e in related_events if e.source_ip})
        unique_users = len({e.username for e in related_events if e.username})

        is_sensitive = float(bool(event.resource and any(x in event.resource.lower() for x in SENSITIVE_RESOURCES)))

        # Active Threat Intel Match
        intel_hit = 0.0
        if event.source_ip:
            hit = db.scalar(
                select(ThreatIndicator.id).where(
                    ThreatIndicator.indicator == event.source_ip,
                    ThreatIndicator.status == "ACTIVE"
                )
            )
            intel_hit = 1.0 if hit else 0.0

        total_auth = failed_count + success_count
        failure_ratio = failed_count / max(1, total_auth)

        # Off-hours & weekend deviations
        hour = event.timestamp.hour
        is_unusual_hour = float(hour < 6 or hour > 21)
        is_weekend = float(event.timestamp.weekday() >= 5)

        # Repetition ratio
        duplicate_ratio = sum(1 for e in related_events if e.event_type == event.event_type) / max(1, len(related_events))

        behavior_dev = round(min(1.0, (is_unusual_hour + is_weekend + failure_ratio) / 3.0), 3)
        corr_score = round(min(1.0, (len(related_events) + unique_ips + unique_users) / 25.0), 3)

        feature = EventFeature(
            event_id=event.id,
            failed_login_count=float(failed_count),
            successful_login_count=float(success_count),
            event_frequency=float(len(related_events)),
            requests_per_minute=float(velocity_rpm),
            unique_ip_count=float(unique_ips),
            unique_user_count=float(unique_users),
            time_of_day_deviation=is_unusual_hour,
            weekend_deviation=is_weekend,
            resource_sensitivity=is_sensitive,
            authentication_failure_ratio=round(failure_ratio, 3),
            repeated_event_score=round(duplicate_ratio, 3),
            source_reputation_score=intel_hit,
            behavioral_deviation=behavior_dev,
            correlation_score=corr_score,
            feature_version="2.0",
        )
        db.add(feature)
        return feature

feature_engine = FeatureEngine()
