"""Safe Non-Destructive Response Simulator Engine for SentinelAI.

Executes containment and remediation workflows in a strictly simulated sandbox:
- Isolate Host (Simulated)
- Disable User Account (Simulated)
- Block IP on Firewall (Simulated)
- Revoke Session Credentials (Simulated)
- Capture Volatile Memory Snapshot (Simulated)

All simulated actions generate immutable audit trail entries without modifying live production infrastructure.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from ..models import ResponseAction, ApprovalRequest, AuditLog
from ..services.audit import audit

SUPPORTED_ACTIONS = {
    "ISOLATE_HOST": {
        "description": "Disconnect target endpoint from internal VLAN and route all network traffic to quarantine sandbox.",
        "simulated_command": "iptables -A FORWARD -s {target} -j DROP; iptables -A FORWARD -d {target} -j DROP",
        "rollback_command": "iptables -D FORWARD -s {target} -j DROP; iptables -D FORWARD -d {target} -j DROP",
        "safety_level": "SIMULATION_SAFE"
    },
    "BLOCK_IP": {
        "description": "Add malicious IP to perimeter edge firewall blacklists and deny ingress connection attempts.",
        "simulated_command": "panos-cli set rule 'AUTO-BLOCK-{target}' action drop from untrust to trust",
        "rollback_command": "panos-cli delete rule 'AUTO-BLOCK-{target}'",
        "safety_level": "SIMULATION_SAFE"
    },
    "DISABLE_USER": {
        "description": "Lock Active Directory user account and expire all active Kerberos / OAuth tokens.",
        "simulated_command": "Disable-ADAccount -Identity '{target}' -Confirm:$false; Revoke-AzureADUserAllRefreshToken",
        "rollback_command": "Enable-ADAccount -Identity '{target}'",
        "safety_level": "SIMULATION_SAFE"
    },
    "REVOKE_CREDENTIALS": {
        "description": "Force password reset flag on next login and flush cached access tokens.",
        "simulated_command": "Set-ADUser -Identity '{target}' -ChangePasswordAtLogon $true",
        "rollback_command": "Write-Output 'Credentials revoked'",
        "safety_level": "SIMULATION_SAFE"
    },
    "FORENSIC_SNAPSHOT": {
        "description": "Dump volatile memory and process tree to secure forensic evidence storage bucket.",
        "simulated_command": "winpmem.exe -o C:\\Forensics\\{target}_memdump.raw; sysmon -c",
        "rollback_command": "N/A",
        "safety_level": "SIMULATION_SAFE"
    }
}

class ResponseSimulator:
    """Simulates active incident response operations safely with audit confirmation."""

    @staticmethod
    def execute_simulated_action(
        db: Session,
        action_type: str,
        target: str,
        analyst_id: str,
        incident_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Execute a simulated mitigation action and record an immutable audit entry."""
        action_upper = action_type.upper().strip()
        template = SUPPORTED_ACTIONS.get(action_upper) or {
            "description": f"Simulated security containment on target: {target}",
            "simulated_command": f"echo 'Executing simulated action {action_upper} on {target}'",
            "rollback_command": "echo 'Rollback complete'",
            "safety_level": "SIMULATION_SAFE"
        }

        rendered_cmd = template["simulated_command"].replace("{target}", target)
        rollback_cmd = template["rollback_command"].replace("{target}", target)
        now_dt = datetime.now(timezone.utc)

        # Create Response Action record
        action_record = ResponseAction(
            incident_id=incident_id,
            action_type=action_upper,
            target=target,
            status="EXECUTED",
            mode="SIMULATED",
            payload={
                "simulated_execution": True,
                "command_rendered": rendered_cmd,
                "rollback_command": rollback_cmd,
                "reason": reason or "Analyst-initiated simulated containment",
                "execution_timestamp": now_dt.isoformat(),
            }
        )
        db.add(action_record)
        
        # Log to Immutable Audit Trail
        audit(
            db=db,
            action="SIMULATED_RESPONSE_EXECUTED",
            resource=f"target:{target}",
            user_id=analyst_id,
            action_type=action_upper,
            incident_id=incident_id,
            simulated=True
        )

        db.commit()
        db.refresh(action_record)

        return {
            "action_id": action_record.id,
            "action_type": action_upper,
            "target": target,
            "status": "SIMULATED_SUCCESS",
            "simulation_badge": "SIMULATION ONLY — SAFE EXECUTION",
            "command_executed": rendered_cmd,
            "rollback_available": rollback_cmd,
            "executed_at": now_dt.isoformat(),
            "analyst_id": analyst_id,
            "description": template["description"]
        }

response_simulator = ResponseSimulator()
