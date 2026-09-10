from datetime import timedelta
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..models import EventFeature, SecurityEvent, ThreatIndicator

SENSITIVE=("/admin","/secrets","/payroll","/production","/config")

def extract_event_features(db:Session,event:SecurityEvent) -> EventFeature:
    start=event.timestamp-timedelta(minutes=60)
    base=select(SecurityEvent).where(SecurityEvent.timestamp>=start)
    entity=base.where((SecurityEvent.source_ip==event.source_ip) | (SecurityEvent.username==event.username))
    related=db.scalars(entity).all() if event.source_ip or event.username else []
    failed=sum(e.status=="FAILURE" for e in related); successful=sum(e.status=="SUCCESS" for e in related)
    minute_start=event.timestamp-timedelta(minutes=1)
    per_minute=sum(e.timestamp>=minute_start for e in related)
    unique_ips=len({e.source_ip for e in related if e.source_ip}); unique_users=len({e.username for e in related if e.username})
    sensitive=float(bool(event.resource and any(x in event.resource.lower() for x in SENSITIVE)))
    intel=float(bool(event.source_ip and db.scalar(select(ThreatIndicator.id).where(ThreatIndicator.indicator==event.source_ip,ThreatIndicator.status=="ACTIVE"))))
    failure_ratio=failed/max(1,failed+successful)
    unusual_hour=float(event.timestamp.hour < 6 or event.timestamp.hour > 21)
    weekend=float(event.timestamp.weekday() >= 5)
    duplicate_ratio=sum(e.event_type==event.event_type for e in related)/max(1,len(related))
    feature=EventFeature(event_id=event.id,failed_login_count=failed,successful_login_count=successful,event_frequency=len(related),requests_per_minute=per_minute,unique_ip_count=unique_ips,unique_user_count=unique_users,time_of_day_deviation=unusual_hour,weekend_deviation=weekend,resource_sensitivity=sensitive,authentication_failure_ratio=failure_ratio,repeated_event_score=duplicate_ratio,source_reputation_score=intel,behavioral_deviation=min(1.0,(unusual_hour+weekend+failure_ratio)/3),correlation_score=min(1.0,(len(related)+unique_ips+unique_users)/25))
    db.add(feature); return feature
