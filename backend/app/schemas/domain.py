from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=160)
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role_requested: str = Field(default="SOC_ANALYST")

class LoginRequest(BaseModel):
    identifier: str | None = None
    email: str | None = None
    password: str
    remember_me: bool = False

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"

class UserOut(ORM):
    id: str
    full_name: str
    username: str | None = None
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None

class UserDetailOut(ORM):
    id: str
    full_name: str
    username: str | None = None
    email: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime | None = None
    last_login_at: datetime | None = None
    failed_login_count: int = 0
    settings_json: dict = Field(default_factory=dict)

class ProfileUpdateRequest(BaseModel):
    full_name: str | None = None
    email: str | None = None
    username: str | None = None
    settings_json: dict | None = None

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

class ForgotPasswordRequest(BaseModel):
    identifier: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

class UserRoleUpdate(BaseModel):
    role: str

class UserStatusUpdate(BaseModel):
    is_active: bool

class EventCreate(BaseModel):
    timestamp: datetime | None = None
    source: str = "manual"
    source_ip: str | None = None
    destination_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    device_id: str | None = None
    event_type: str
    category: str = "authentication"
    action: str | None = None
    status: str | None = None
    resource: str | None = None
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    user_agent: str | None = None
    severity: str = "LOW"
    raw_message: str | None = None
    metadata_json: dict[str, Any] = Field(default_factory=dict)
    synthetic: bool = False

class EventOut(ORM):
    id: str
    event_id: str
    timestamp: datetime
    source: str
    source_ip: str | None
    destination_ip: str | None = None
    username: str | None
    hostname: str | None = None
    event_type: str
    category: str
    status: str | None
    resource: str | None
    severity: str
    synthetic: bool
    metadata_json: dict

class RuleCreate(BaseModel):
    name: str
    description: str
    rule_type: str = "threshold"
    config: dict = Field(default_factory=dict)
    severity: str = "MEDIUM"
    enabled: bool = True

class RuleTestRequest(BaseModel):
    rule_config: dict
    event_payload: dict

class StatusUpdate(BaseModel):
    status: str
    note: str | None = None

class IncidentUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    assigned_to: str | None = None
    root_cause: str | None = None
    resolution: str | None = None

class NoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=2000)

class IndicatorCreate(BaseModel):
    indicator: str
    indicator_type: str
    risk_level: str
    description: str = ""
    source: str = "local"

class SimulationRequest(BaseModel):
    scenario: str = "mixed"
    count: int = Field(default=100, ge=1, le=5000)
    seed: int = 42

class ResponseRequest(BaseModel):
    incident_id: str | None = None
    action_type: str
    mode: str = "APPROVAL_REQUIRED"
    payload: dict = Field(default_factory=dict)
    reason: str = "Analyst-requested response"

class ApprovalDecision(BaseModel):
    approved: bool
    note: str = ""

class MLTrainRequest(BaseModel):
    sample_size: int = Field(default=2000, ge=100, le=20000)
    contamination: float = Field(default=0.08, ge=0.01, le=0.5)

class MLScoreRequest(BaseModel):
    event_id: str | None = None
    features: dict[str, float] | None = None
