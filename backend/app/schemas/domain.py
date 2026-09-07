from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field

class ORM(BaseModel): model_config = ConfigDict(from_attributes=True)
class RegisterRequest(BaseModel): full_name: str = Field(min_length=2, max_length=160); email: EmailStr; password: str = Field(min_length=10, max_length=128)
class LoginRequest(BaseModel): email: EmailStr; password: str
class TokenResponse(BaseModel): access_token: str; token_type: str = "bearer"; user: "UserOut"
class UserOut(ORM): id: str; full_name: str; email: EmailStr; role: str; is_active: bool; created_at: datetime
class EventCreate(BaseModel):
    timestamp: datetime | None = None; source: str = "manual"; source_ip: str | None = None; destination_ip: str | None = None
    username: str | None = None; hostname: str | None = None; device_id: str | None = None; event_type: str
    category: str = "authentication"; action: str | None = None; status: str | None = None; resource: str | None = None
    protocol: str | None = None; port: int | None = Field(default=None, ge=0, le=65535); user_agent: str | None = None
    severity: str = "LOW"; raw_message: str | None = None; metadata_json: dict[str, Any] = Field(default_factory=dict); synthetic: bool = False
class EventOut(ORM): id: str; event_id: str; timestamp: datetime; source: str; source_ip: str | None; username: str | None; event_type: str; category: str; status: str | None; resource: str | None; severity: str; synthetic: bool; metadata_json: dict
class RuleCreate(BaseModel): name: str; description: str; rule_type: str = "threshold"; config: dict = Field(default_factory=dict); severity: str = "MEDIUM"; enabled: bool = True
class StatusUpdate(BaseModel): status: str; note: str | None = None
class NoteCreate(BaseModel): note: str = Field(min_length=1, max_length=2000)
class IndicatorCreate(BaseModel): indicator: str; indicator_type: str; risk_level: str; description: str = ""; source: str = "local"
class SimulationRequest(BaseModel): scenario: str = "mixed"; count: int = Field(default=100, ge=1, le=5000); seed: int = 42
class ResponseRequest(BaseModel): incident_id: str | None = None; action_type: str; mode: str = "APPROVAL_REQUIRED"; payload: dict = Field(default_factory=dict); reason: str = "Analyst-requested response"
class ApprovalDecision(BaseModel): approved: bool; note: str = ""
