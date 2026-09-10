"""AI Mitigation Playbook & Root Cause Generation Engine for SentinelAI SOC.

Analyzes security incidents, aggregated alert metadata, and threat indicators
to formulate structured, tactical containment and eradication playbooks.
"""
from __future__ import annotations
from typing import Any, Dict, List
from ..models import Incident, Alert, SecurityEvent


def generate_incident_playbook(incident: Incident, alerts: List[Alert], events: List[SecurityEvent]) -> Dict[str, Any]:
    """Generates an intelligent step-by-step incident response playbook and forensic assessment."""
    threat_category = "GENERAL_ANOMALY"
    affected_ips = set()
    affected_users = set()
    affected_hosts = set()
    indicators = []

    for alert in alerts:
        if alert.entities:
            if "source_ip" in alert.entities and alert.entities["source_ip"]:
                affected_ips.add(alert.entities["source_ip"])
            if "username" in alert.entities and alert.entities["username"]:
                affected_users.add(alert.entities["username"])
            if "hostname" in alert.entities and alert.entities["hostname"]:
                affected_hosts.add(alert.entities["hostname"])

    for event in events:
        if event.source_ip:
            affected_ips.add(event.source_ip)
        if event.username:
            affected_users.add(event.username)
        if event.hostname:
            affected_hosts.add(event.hostname)

    # Determine dominant threat profile
    titles = " ".join([a.title.lower() for a in alerts] + [incident.title.lower()])
    if "brute" in titles or "failed" in titles or "password" in titles:
        threat_category = "CREDENTIAL_ATTACK"
    elif "sql" in titles or "injection" in titles or "xss" in titles or "exploit" in titles:
        threat_category = "WEB_APPLICATION_EXPLOIT"
    elif "port" in titles or "scan" in titles or "recon" in titles:
        threat_category = "RECONNAISSANCE"
    elif "privilege" in titles or "admin" in titles or "escalation" in titles:
        threat_category = "PRIVILEGE_ESCALATION"
    elif "lateral" in titles or "smb" in titles or "rdp" in titles:
        threat_category = "LATERAL_MOVEMENT"
    elif "exfiltration" in titles or "outbound" in titles or "c2" in titles:
        threat_category = "DATA_EXFILTRATION_C2"

    # Assemble forensic hypothesis
    hypothesis = _generate_hypothesis(threat_category, affected_ips, affected_users, affected_hosts, incident.severity)

    # Assemble phased response steps
    playbook_steps = _generate_phased_steps(threat_category, list(affected_ips), list(affected_users), list(affected_hosts))

    # Suggested automated response actions
    suggested_actions = []
    for ip in affected_ips:
        suggested_actions.append({
            "action_type": "BLOCK_IP",
            "target": ip,
            "mode": "APPROVAL_REQUIRED",
            "reason": f"Contain potential attacker communications from source IP {ip}",
            "impact": "Inbound and outbound network traffic dropped at edge firewall.",
        })
    for user in affected_users:
        suggested_actions.append({
            "action_type": "REVOKE_SESSION",
            "target": user,
            "mode": "APPROVAL_REQUIRED",
            "reason": f"Invalidate active access tokens and force credential reset for {user}",
            "impact": "User session invalidated; next request will require re-authentication.",
        })
    for host in affected_hosts:
        suggested_actions.append({
            "action_type": "QUARANTINE_HOST",
            "target": host,
            "mode": "APPROVAL_REQUIRED",
            "reason": f"Isolate endpoint {host} on management VLAN to prevent lateral spread",
            "impact": "Endpoint network interface restricted to SOC management subnet only.",
        })

    return {
        "incident_id": incident.id,
        "threat_category": threat_category,
        "confidence_level": incident.confidence,
        "forensic_hypothesis": hypothesis,
        "affected_entities": {
            "source_ips": sorted(list(affected_ips)),
            "usernames": sorted(list(affected_users)),
            "hostnames": sorted(list(affected_hosts)),
        },
        "response_playbook": playbook_steps,
        "suggested_actions": suggested_actions,
    }


def _generate_hypothesis(category: str, ips: set, users: set, hosts: set, severity: str) -> str:
    ip_str = ", ".join(list(ips)[:3]) or "external/unknown origin"
    user_str = ", ".join(list(users)[:3]) or "system accounts"
    host_str = ", ".join(list(hosts)[:3]) or "internal network endpoints"

    hypotheses = {
        "CREDENTIAL_ATTACK": f"Adversary initiated automated credential spray / brute force from {ip_str} targeting identity accounts ({user_str}). The pattern demonstrates velocity-based authentication anomalies requiring immediate session invalidation.",
        "WEB_APPLICATION_EXPLOIT": f"Potential exploitation payload identified against web tier targeting resource endpoints from {ip_str}. Input parameter anomaly indicates injection attempts.",
        "RECONNAISSANCE": f"Systematic port/endpoint scanning observed originating from {ip_str} probing host infrastructure ({host_str}) for open listening services.",
        "PRIVILEGE_ESCALATION": f"High-risk permission escalation detected for account {user_str} on {host_str} exhibiting deviations from normal role baseline.",
        "LATERAL_MOVEMENT": f"Suspicious inter-host traversal detected originating from {host_str} utilizing internal administrative protocols.",
        "DATA_EXFILTRATION_C2": f"Unusual volumetric outbound data transfer or beaconing rhythm detected to remote destination {ip_str}.",
        "GENERAL_ANOMALY": f"Multivariate behavioral anomalies detected across {ip_str} and {user_str} exceeding normal statistical thresholds ({severity} severity rating).",
    }
    return hypotheses.get(category, hypotheses["GENERAL_ANOMALY"])


def _generate_phased_steps(category: str, ips: list, users: list, hosts: list) -> List[Dict[str, Any]]:
    return [
        {
            "phase": "Phase 1: Immediate Containment",
            "priority": "P0 - CRITICAL",
            "actions": [
                f"Block IP address(es) [{', '.join(ips) or 'suspicious origin'}] at the perimeter firewall." if ips else "Audit edge firewall rules for unusual traffic flows.",
                f"Invalidate active OAuth/SAML tokens and force password reset for [{', '.join(users) or 'compromised identities'}]." if users else "Review recent identity provider login sessions.",
                f"Isolate host(s) [{', '.join(hosts) or 'impacted endpoints'}] from the production network into containment VLAN." if hosts else "Verify endpoint integrity via EDR agents.",
            ]
        },
        {
            "phase": "Phase 2: Forensic Eradication",
            "priority": "P1 - HIGH",
            "actions": [
                "Extract system memory dumps and volatile telemetry from impacted endpoints before full remediation.",
                "Scan affected systems for persistence mechanisms (cron jobs, registry autoruns, SSH authorized_keys).",
                "Review web server and database access logs 24 hours prior to incident onset.",
            ]
        },
        {
            "phase": "Phase 3: Recovery & Verification",
            "priority": "P2 - MEDIUM",
            "actions": [
                "Restore affected configurations or deploy clean golden images to quarantined hosts.",
                "Re-enable identity accounts with mandatory multi-factor authentication (MFA) step-up.",
                "Perform continuous 48-hour heightened synthetic monitoring on affected entity fingerprints.",
            ]
        },
        {
            "phase": "Phase 4: Post-Incident Lessons Learned",
            "priority": "P3 - LOW",
            "actions": [
                "Update detection threshold rules to lower MTTA for similar attack vectors.",
                "Publish IOC hashes and IP artifacts to local Threat Intelligence feed.",
                "Generate and archive comprehensive forensic PDF investigation report for compliance audit.",
            ]
        }
    ]
