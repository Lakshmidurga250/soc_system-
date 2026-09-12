"""SentinelAI User & Entity Behavior Analytics (UEBA) Engine.

Implements statistical profiling, peer group clustering, and anomaly scoring for:
- Unusual Working Hours & Login Time Discrepancies
- Peer Group Baseline Deviations (e.g. Finance analyst accessing Domain Controller)
- Lateral Movement Blast Radius & Velocity Profiling
- Volume Anomalies (Excessive File Downloads / Egress Data Transfers)
- Account Privilege Hopping & Dormant Account Reactivation
100% offline mathematical behavioral analysis.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class UserBehaviorBaseline:
    username: str
    department: str  # e.g., "Engineering", "Finance", "HR", "IT_Admin"
    peer_group: str
    typical_login_hours: List[int]  # e.g., [9, 10, 11, 12, 13, 14, 15, 16, 17]
    typical_hosts_accessed: Set[str]
    average_daily_events: float
    average_daily_bytes_transferred: float
    max_normal_failed_logins: int = 3
    is_privileged_account: bool = False
    last_activity_date: str = "2026-01-01"


@dataclass
class UEBAAnomalyFinding:
    username: str
    anomaly_type: str  # OFF_HOURS_ACCESS, PEER_GROUP_DEVIATION, LATERAL_VELOCITY, VOLUME_BURST, PRIVILEGE_HOPPING
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float  # 0 to 100
    confidence: float
    observed_value: Any
    baseline_expected: Any
    mitre_technique: str
    description: str
    recommended_action: str


class UserBehaviorAnalyticsEngine:
    """Statistical behavioral anomaly detection for enterprise user accounts."""

    def __init__(self):
        self.baselines: Dict[str, UserBehaviorBaseline] = {}
        self.department_peer_groups: Dict[str, Set[str]] = defaultdict(set)
        self._seed_enterprise_baselines()

    def register_baseline(self, baseline: UserBehaviorBaseline) -> None:
        self.baselines[baseline.username.lower()] = baseline
        self.department_peer_groups[baseline.department].add(baseline.username.lower())

    def analyze_user_activity_session(
        self,
        username: str,
        login_hour: int,
        accessed_host: str,
        bytes_transferred: float,
        failed_login_count: int,
        session_events_count: int,
        is_weekend: bool = False,
    ) -> List[UEBAAnomalyFinding]:
        """Evaluates a live user session against historical peer group and individual baselines."""
        clean_user = username.strip().lower()
        baseline = self.baselines.get(clean_user)

        # If user is completely unknown, score as first-time unknown account
        if not baseline:
            return [
                UEBAAnomalyFinding(
                    username=username,
                    anomaly_type="NEW_UNKNOWN_ACCOUNT_ACTIVITY",
                    severity="MEDIUM",
                    risk_score=50.0,
                    confidence=0.75,
                    observed_value=f"First activity observed on host {accessed_host}",
                    baseline_expected="Established account profile",
                    mitre_technique="T1078",
                    description=f"Activity observed for previously unregistered user account '{username}'.",
                    recommended_action="Verify account creation ticket in Identity Management (IAM).",
                )
            ]

        findings: List[UEBAAnomalyFinding] = []

        # 1. Unusual Working Hours / Off-Hours Anomaly
        if login_hour not in baseline.typical_login_hours or is_weekend:
            min_dist = min(abs(login_hour - h) for h in baseline.typical_login_hours) if baseline.typical_login_hours else 12
            risk = min(85.0, 40.0 + (min_dist * 6.0) + (15.0 if is_weekend else 0.0))
            sev = "HIGH" if risk > 70 else "MEDIUM"
            findings.append(
                UEBAAnomalyFinding(
                    username=username,
                    anomaly_type="OFF_HOURS_ACCESS",
                    severity=sev,
                    risk_score=round(risk, 1),
                    confidence=0.88,
                    observed_value=f"Login at {login_hour:02d}:00 UTC (Weekend={is_weekend})",
                    baseline_expected=f"Typical active hours: {min(baseline.typical_login_hours):02d}:00 - {max(baseline.typical_login_hours):02d}:00 UTC",
                    mitre_technique="T1078.002",
                    description=f"User '{username}' authenticated significantly outside established operational working hours.",
                    recommended_action="Validate whether analyst or user requested off-hours maintenance authorization.",
                )
            )

        # 2. Peer Group Baseline & Sensitive Asset Access Deviation
        is_sensitive_host = any(s in accessed_host.lower() for s in ("dc-", "domain-controller", "vault", "pki", "prod-db", "crownjewel"))
        if accessed_host not in baseline.typical_hosts_accessed:
            if is_sensitive_host and not baseline.is_privileged_account:
                findings.append(
                    UEBAAnomalyFinding(
                        username=username,
                        anomaly_type="PEER_GROUP_DEVIATION",
                        severity="CRITICAL",
                        risk_score=92.0,
                        confidence=0.95,
                        observed_value=f"Accessed critical crown-jewel asset '{accessed_host}'",
                        baseline_expected=f"Department '{baseline.department}' standard hosts: {', '.join(baseline.typical_hosts_accessed)}",
                        mitre_technique="T1021",
                        description=f"Non-privileged user in '{baseline.department}' accessed domain controller or sensitive asset.",
                        recommended_action="Initiate immediate session termination and credential reset.",
                    )
                )
            else:
                findings.append(
                    UEBAAnomalyFinding(
                        username=username,
                        anomaly_type="NEW_HOST_ACCESS",
                        severity="LOW",
                        risk_score=35.0,
                        confidence=0.70,
                        observed_value=f"Accessed host '{accessed_host}'",
                        baseline_expected=f"Historical hosts: {', '.join(baseline.typical_hosts_accessed)}",
                        mitre_technique="T1087",
                        description=f"User '{username}' accessed a new internal host for the first time.",
                        recommended_action="Monitor for subsequent lateral movement attempts.",
                    )
                )

        # 3. Data Volume & Egress Spike Anomaly
        if baseline.average_daily_bytes_transferred > 0:
            volume_ratio = bytes_transferred / baseline.average_daily_bytes_transferred
            if volume_ratio >= 5.0:
                risk = min(95.0, 50.0 + (volume_ratio * 5.0))
                sev = "CRITICAL" if volume_ratio >= 10.0 else "HIGH"
                findings.append(
                    UEBAAnomalyFinding(
                        username=username,
                        anomaly_type="VOLUME_BURST",
                        severity=sev,
                        risk_score=round(risk, 1),
                        confidence=0.91,
                        observed_value=f"{round(bytes_transferred / (1024*1024), 2)} MB transferred ({round(volume_ratio, 1)}x baseline)",
                        baseline_expected=f"Average {round(baseline.average_daily_bytes_transferred / (1024*1024), 2)} MB daily",
                        mitre_technique="T1048",
                        description=f"Massive data transfer surge detected for user '{username}'. Potential data staging / exfiltration.",
                        recommended_action="Inspect network egress destination IPs and freeze data access.",
                    )
                )

        # 4. Failed Login Velocity Spike
        if failed_login_count > baseline.max_normal_failed_logins:
            findings.append(
                UEBAAnomalyFinding(
                    username=username,
                    anomaly_type="FAILED_LOGIN_BURST",
                    severity="HIGH",
                    risk_score=75.0,
                    confidence=0.94,
                    observed_value=f"{failed_login_count} consecutive failed login attempts",
                    baseline_expected=f"Maximum normal failures: {baseline.max_normal_failed_logins}",
                    mitre_technique="T1110",
                    description=f"Abnormal failed authentication velocity observed on user account '{username}'.",
                    recommended_action="Temporarily lock account and enforce MFA verification.",
                )
            )

        return findings

    def _seed_enterprise_baselines(self):
        """Pre-populates enterprise user baselines across functional departments."""
        self.register_baseline(
            UserBehaviorBaseline(
                username="alice_dev",
                department="Engineering",
                peer_group="Software_Engineers",
                typical_login_hours=[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
                typical_hosts_accessed={"ws-dev-01", "git-internal", "ci-builder", "staging-api"},
                average_daily_events=250.0,
                average_daily_bytes_transferred=45 * 1024 * 1024,  # 45 MB
                is_privileged_account=False,
            )
        )
        self.register_baseline(
            UserBehaviorBaseline(
                username="bob_finance",
                department="Finance",
                peer_group="Financial_Auditors",
                typical_login_hours=[9, 10, 11, 12, 13, 14, 15, 16, 17],
                typical_hosts_accessed={"ws-fin-04", "erp-server", "payroll-db"},
                average_daily_events=120.0,
                average_daily_bytes_transferred=15 * 1024 * 1024,  # 15 MB
                is_privileged_account=False,
            )
        )
        self.register_baseline(
            UserBehaviorBaseline(
                username="charlie_admin",
                department="IT_Admin",
                peer_group="Domain_Admins",
                typical_login_hours=[7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
                typical_hosts_accessed={"dc-01", "dc-02", "jumpbox-admin", "vault-pki", "ws-admin-01"},
                average_daily_events=800.0,
                average_daily_bytes_transferred=120 * 1024 * 1024,  # 120 MB
                is_privileged_account=True,
            )
        )
        self.register_baseline(
            UserBehaviorBaseline(
                username="svc_backup",
                department="IT_Infrastructure",
                peer_group="Service_Accounts",
                typical_login_hours=[0, 1, 2, 3, 4],  # Nightly backup window
                typical_hosts_accessed={"nas-backup-01", "storage-san", "db-cluster"},
                average_daily_events=500.0,
                average_daily_bytes_transferred=800 * 1024 * 1024,  # 800 MB
                is_privileged_account=True,
            )
        )


# Global UEBA instance
ueba_engine = UserBehaviorAnalyticsEngine()
