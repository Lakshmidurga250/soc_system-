"""Role-Based Access Control (RBAC) definitions and permissions."""
from enum import Enum
from typing import Set

class Role(str, Enum):
    ADMIN = "ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    INVESTIGATOR = "INVESTIGATOR"
    VIEWER = "VIEWER"

class Permission(str, Enum):
    # Events & Logs
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"
    
    # Alerts
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"
    ALERTS_TRIAGE = "alerts:triage"
    
    # Incidents
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    INCIDENTS_INVESTIGATE = "incidents:investigate"
    
    # Rules
    RULES_READ = "rules:read"
    RULES_WRITE = "rules:write"
    
    # Threat Intelligence
    INTEL_READ = "intel:read"
    INTEL_WRITE = "intel:write"
    
    # ML & Optimization
    ML_READ = "ml:read"
    ML_TRAIN = "ml:train"
    
    # Response & Approvals
    RESPONSE_EXECUTE = "response:execute"
    APPROVALS_DECIDE = "approvals:decide"
    
    # Administration
    USERS_MANAGE = "users:manage"
    SYSTEM_CONFIG = "system:config"
    AUDIT_READ = "audit:read"
    SIMULATION_RUN = "simulation:run"

ROLE_PERMISSIONS: dict[Role, Set[Permission]] = {
    Role.ADMIN: set(Permission),
    Role.SOC_ANALYST: {
        Permission.EVENTS_READ,
        Permission.EVENTS_INGEST,
        Permission.ALERTS_READ,
        Permission.ALERTS_WRITE,
        Permission.ALERTS_TRIAGE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_CREATE,
        Permission.INCIDENTS_UPDATE,
        Permission.INCIDENTS_INVESTIGATE,
        Permission.RULES_READ,
        Permission.RULES_WRITE,
        Permission.INTEL_READ,
        Permission.INTEL_WRITE,
        Permission.ML_READ,
        Permission.ML_TRAIN,
        Permission.RESPONSE_EXECUTE,
        Permission.APPROVALS_DECIDE,
        Permission.AUDIT_READ,
        Permission.SIMULATION_RUN,
    },
    Role.INVESTIGATOR: {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.ALERTS_TRIAGE,
        Permission.INCIDENTS_READ,
        Permission.INCIDENTS_INVESTIGATE,
        Permission.RULES_READ,
        Permission.INTEL_READ,
        Permission.ML_READ,
        Permission.RESPONSE_EXECUTE,
        Permission.AUDIT_READ,
    },
    Role.VIEWER: {
        Permission.EVENTS_READ,
        Permission.ALERTS_READ,
        Permission.INCIDENTS_READ,
        Permission.RULES_READ,
        Permission.INTEL_READ,
        Permission.ML_READ,
        Permission.AUDIT_READ,
    },
}

def has_permission(role_str: str, permission: Permission) -> bool:
    try:
        role = Role(role_str)
        return permission in ROLE_PERMISSIONS.get(role, set())
    except ValueError:
        return False
