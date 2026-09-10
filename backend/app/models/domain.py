"""Comprehensive SQLAlchemy 2.0 Domain Models for SentinelAI SOC Platform."""
from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, Index, UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from ..core.database import Base

def uid() -> str:
    return str(uuid4())

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class Timestamped:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

# ==================== AUTH & IDENTITY ====================
class User(Timestamped, Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    full_name: Mapped[str] = mapped_column(String(160), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="SOC_ANALYST", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reset_token: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    settings_json: Mapped[dict] = mapped_column(JSON, default=dict)

class LoginHistory(Base):
    __tablename__ = "login_histories"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    email_attempted: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="SUCCESS")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

# ==================== TELEMETRY & EVENTS ====================
class SecurityEvent(Timestamped, Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True, default=uid)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    source: Mapped[str] = mapped_column(String(100), default="manual", index=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(160), nullable=True, index=True)
    device_id: Mapped[str | None] = mapped_column(String(160), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    category: Mapped[str] = mapped_column(String(100), default="authentication", index=True)
    action: Mapped[str | None] = mapped_column(String(100), nullable=True)
    status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(32), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="LOW", index=True)
    raw_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    
    __table_args__ = (
        Index("ix_event_entity_time", "source_ip", "username", "timestamp"),
    )

class NormalizedEvent(Timestamped, Base):
    __tablename__ = "normalized_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    raw_event_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), index=True)
    canonical_schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    normalized_data: Mapped[dict] = mapped_column(JSON, default=dict)

class IngestionBatch(Timestamped, Base):
    __tablename__ = "ingestion_batches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    filename: Mapped[str] = mapped_column(String(255))
    source_format: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(100), default="upload")
    checksum: Mapped[str] = mapped_column(String(64), index=True)
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    accepted_records: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_records: Mapped[int] = mapped_column(Integer, default=0)
    malformed_records: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSON, default=list)

# ==================== FEATURES & ML ====================
class EventFeature(Timestamped, Base):
    __tablename__ = "event_features"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), unique=True, index=True)
    failed_login_count: Mapped[float] = mapped_column(Float, default=0)
    successful_login_count: Mapped[float] = mapped_column(Float, default=0)
    event_frequency: Mapped[float] = mapped_column(Float, default=0)
    requests_per_minute: Mapped[float] = mapped_column(Float, default=0)
    unique_ip_count: Mapped[float] = mapped_column(Float, default=0)
    unique_user_count: Mapped[float] = mapped_column(Float, default=0)
    time_of_day_deviation: Mapped[float] = mapped_column(Float, default=0)
    weekend_deviation: Mapped[float] = mapped_column(Float, default=0)
    resource_sensitivity: Mapped[float] = mapped_column(Float, default=0)
    authentication_failure_ratio: Mapped[float] = mapped_column(Float, default=0)
    repeated_event_score: Mapped[float] = mapped_column(Float, default=0)
    source_reputation_score: Mapped[float] = mapped_column(Float, default=0)
    behavioral_deviation: Mapped[float] = mapped_column(Float, default=0)
    correlation_score: Mapped[float] = mapped_column(Float, default=0)
    feature_version: Mapped[str] = mapped_column(String(32), default="1.0")

class MLModel(Timestamped, Base):
    __tablename__ = "ml_models"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(128), unique=True)
    model_type: Mapped[str] = mapped_column(String(64))  # IsolationForest, RandomForest, KMeans
    version: Mapped[str] = mapped_column(String(32), default="1.0.0")
    file_path: Mapped[str] = mapped_column(String(512))
    metrics_json: Mapped[dict] = mapped_column(JSON, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

class MLTrainingRun(Timestamped, Base):
    __tablename__ = "ml_training_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    model_id: Mapped[str] = mapped_column(String(36), ForeignKey("ml_models.id", ondelete="CASCADE"), index=True)
    samples_count: Mapped[int] = mapped_column(Integer)
    hyperparameters: Mapped[dict] = mapped_column(JSON, default=dict)
    evaluation_scores: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="COMPLETED")

# ==================== RULES & DETECTIONS ====================
class DetectionRule(Timestamped, Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    name: Mapped[str] = mapped_column(String(160), unique=True)
    description: Mapped[str] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(String(64), default="threshold")
    category: Mapped[str] = mapped_column(String(64), default="authentication")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    severity: Mapped[str] = mapped_column(String(16), default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    execution_count: Mapped[int] = mapped_column(Integer, default=0)
    match_count: Mapped[int] = mapped_column(Integer, default=0)

class RuleExecution(Base):
    __tablename__ = "rule_executions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    rule_id: Mapped[str] = mapped_column(String(36), ForeignKey("detection_rules.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_events.id", ondelete="CASCADE"), index=True)
    matched: Mapped[bool] = mapped_column(Boolean)
    execution_time_ms: Mapped[float] = mapped_column(Float, default=0.0)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

# ==================== ALERTS & INCIDENTS ====================
class Alert(Timestamped, Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(64))  # rule_engine, ml_engine, behavior_engine
    detection_method: Mapped[str] = mapped_column(String(64), default="RULE")
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    confidence_score: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(32), default="NEW", index=True)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    entities: Mapped[dict] = mapped_column(JSON, default=dict)
    explanation: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[list] = mapped_column(JSON, default=list)

class Incident(Timestamped, Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    title: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[float] = mapped_column(Float)
    confidence: Mapped[float] = mapped_column(Float)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    alert_ids: Mapped[list] = mapped_column(JSON, default=list)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)

# ==================== INVESTIGATIONS & EVIDENCE ====================
class Investigation(Timestamped, Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str] = mapped_column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(32), default="RUNNING")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    statistics: Mapped[dict] = mapped_column(JSON, default=dict)

class InvestigationStep(Timestamped, Base):
    __tablename__ = "investigation_steps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    investigation_id: Mapped[str] = mapped_column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    step_number: Mapped[int] = mapped_column(Integer)
    action_name: Mapped[str] = mapped_column(String(128))
    rationale: Mapped[str] = mapped_column(Text)
    expected_information_gain: Mapped[float] = mapped_column(Float, default=0.0)
    computational_cost: Mapped[float] = mapped_column(Float, default=1.0)
    status: Mapped[str] = mapped_column(String(32), default="COMPLETED")
    findings_json: Mapped[dict] = mapped_column(JSON, default=dict)

# ==================== SECURITY KNOWLEDGE GRAPH ====================
class Entity(Timestamped, Base):
    __tablename__ = "entities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)  # User, Host, IP, Process, File, Domain
    value: Mapped[str] = mapped_column(String(255), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    
    __table_args__ = (
        UniqueConstraint("entity_type", "value", name="uq_entity_type_value"),
    )

class Relationship(Timestamped, Base):
    __tablename__ = "relationships"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    source_entity_id: Mapped[str] = mapped_column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    target_entity_id: Mapped[str] = mapped_column(String(36), ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    relation_type: Mapped[str] = mapped_column(String(64), index=True)  # LOGIN_FROM, ACCESSED, CONNECTED_TO, TRIGGERED
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

# ==================== THREAT INTELLIGENCE ====================
class ThreatIndicator(Timestamped, Base):
    __tablename__ = "threat_indicators"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    indicator: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(32), index=True)  # IP, Domain, Hash, URL
    risk_level: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(160), default="local")
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

# ==================== RESPONSE & APPROVALS ====================
class ResponseAction(Timestamped, Base):
    __tablename__ = "response_actions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    incident_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(100))  # BLOCK_IP, QUARANTINE_HOST, REVOKE_SESSION, ISOLATE_PROCESS
    target: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    mode: Mapped[str] = mapped_column(String(32), default="APPROVAL_REQUIRED")
    status: Mapped[str] = mapped_column(String(32), default="PENDING")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    executed_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

class ApprovalRequest(Timestamped, Base):
    __tablename__ = "approval_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    response_action_id: Mapped[str] = mapped_column(String(36), ForeignKey("response_actions.id", ondelete="CASCADE"), index=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    decision_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)

# ==================== AUDIT & SIMULATION ====================
class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(128), index=True)
    resource: Mapped[str] = mapped_column(String(255))
    result: Mapped[str] = mapped_column(String(32), default="SUCCESS")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

class SimulationRun(Timestamped, Base):
    __tablename__ = "simulation_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    scenario: Mapped[str] = mapped_column(String(64))
    seed: Mapped[int] = mapped_column(Integer)
    requested_count: Mapped[int] = mapped_column(Integer)
    generated_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="COMPLETED")
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)

class SystemSetting(Timestamped, Base):
    __tablename__ = "system_settings"
    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    description: Mapped[str | None] = mapped_column(String(512), nullable=True)

# ==================== ASSET INVENTORY ====================
class Asset(Timestamped, Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    hostname: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    asset_type: Mapped[str] = mapped_column(String(64), default="SERVER")  # SERVER, WORKSTATION, GATEWAY, DATABASE
    criticality: Mapped[str] = mapped_column(String(16), default="TIER_2")  # TIER_1 (Critical), TIER_2, TIER_3, TIER_4
    operating_system: Mapped[str | None] = mapped_column(String(128), nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

