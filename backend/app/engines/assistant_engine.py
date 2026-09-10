"""Local Deterministic SOC Investigation Assistant Engine.

Answers structured investigation queries using the application's actual stored telemetry:
- What happened?
- Why was this alert/incident generated?
- Which assets and user accounts are affected?
- What evidence supports this finding?
- Why is the risk score high?
- What should the analyst investigate next?
"""
from typing import Dict, List, Any, Optional
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from ..models import Incident, Alert, SecurityEvent
from ..intelligence.mitre_mapper import mitre_mapper

class LocalInvestigationAssistant:
    """Deterministic local SOC assistant that generates contextual investigation answers from database entities."""

    def query_incident_investigation(self, db: Session, incident_id: str, question: str) -> Dict[str, Any]:
        """Answer structured investigation questions for a specific incident."""
        incident = db.get(Incident, incident_id)
        if not incident:
            return {
                "question": question,
                "answer": f"Incident {incident_id} not found in database.",
                "evidence_references": [],
                "suggested_next_steps": ["Verify incident identifier in the incident queue."]
            }

        # Retrieve correlated alerts
        alerts = []
        if incident.alert_ids:
            alerts = db.scalars(select(Alert).where(Alert.id.in_(incident.alert_ids))).all()

        # Extract entities and attack types
        attack_types = list({a.title for a in alerts})
        if not attack_types:
            attack_types = [incident.title or "Anomalous Activity"]
        source_ips = list({a.entities.get("source_ip") for a in alerts if a.entities and a.entities.get("source_ip")})
        usernames = list({a.entities.get("username") for a in alerts if a.entities and a.entities.get("username")})
        mitre_data = mitre_mapper.map_category(attack_types[0] if attack_types else "Anomalous Activity")

        q_lower = question.lower()
        evidence_refs = [f"Alert: {a.title} (Severity: {a.severity}, Risk: {a.risk_score})" for a in alerts[:5]]

        if "what happened" in q_lower or "summary" in q_lower or "explain" in q_lower:
            answer = (
                f"Incident '{incident.title}' was triggered with a composite Risk Score of {incident.risk_score}/100 ({incident.severity} severity). "
                f"It encompasses {len(alerts)} correlated security alerts originating from {len(source_ips)} source IP(s) "
                f"({', '.join(source_ips) if source_ips else 'N/A'}) targeting {len(usernames)} user account(s) "
                f"({', '.join(usernames) if usernames else 'system/infrastructure'}). "
                f"The observed progression aligns with MITRE ATT&CK Tactic '{mitre_data['tactic']}' ({mitre_data['technique_id']}: {mitre_data['technique']})."
            )
            next_steps = [
                f"Review network telemetry for source IP(s): {', '.join(source_ips) if source_ips else 'N/A'}",
                f"Inspect authentication logs for affected user(s): {', '.join(usernames) if usernames else 'N/A'}",
                f"Execute containment action for '{mitre_data['technique']}' mitigation."
            ]

        elif "why was this alert generated" in q_lower or "detection" in q_lower or "rule" in q_lower:
            answer = (
                f"Detection rules triggered due to specific behavioral threshold violations. "
                f"Dominant detection pattern: {attack_types[0] if attack_types else 'Behavioral Anomaly'}. "
                f"Root cause assessment: {incident.root_cause or 'Multiple correlated authentication/traffic anomalies detected within 15-minute sliding correlation window.'}"
            )
            next_steps = [
                "Verify threshold limits in the Detection Rules configuration tab.",
                "Review raw JSON payload of the initial trigger event."
            ]

        elif "which asset" in q_lower or "who is affected" in q_lower or "entities" in q_lower:
            answer = (
                f"The investigation isolated the following entity blast radius: "
                f"Target User Accounts: {', '.join(usernames) if usernames else 'Local Service/Root'}. "
                f"Adversary / Remote IPs: {', '.join(source_ips) if source_ips else 'Internal Subnet'}. "
                f"Total Correlated Events: {len(alerts)} detection alerts."
            )
            next_steps = [
                "Check Asset Inventory criticality rating for target endpoints.",
                "Isolate compromised host if risk score exceeds 75."
            ]

        elif "why is the risk high" in q_lower or "risk score" in q_lower or "score" in q_lower:
            answer = (
                f"The risk score of {incident.risk_score}/100 was computed using a multi-factor transparent formula: "
                f"(1) Peak alert severity weighting: {incident.severity} tier. "
                f"(2) Volume of correlated alerts: {len(alerts)} distinct alerts aggregated. "
                f"(3) Attack classification: '{attack_types[0] if attack_types else 'Generic'}' mapped to critical MITRE technique {mitre_data['technique_id']}. "
                f"(4) Confidence score: {round((incident.confidence or 0.85) * 100, 1)}%."
            )
            next_steps = [
                "Review False Positive probability in Analytics tab.",
                "Verify if the source IP has prior malicious reputation entries."
            ]

        elif "what should i do" in q_lower or "next" in q_lower or "recommend" in q_lower or "action" in q_lower:
            answer = (
                f"Recommended SOC Response Workflow for {mitre_data['technique']}: "
                f"1. Containment: {mitre_data['mitigation']} "
                f"2. Eradication: Terminate unauthorized sessions and revoke active JWT/Kerberos tokens. "
                f"3. Recovery: Audit password resets and monitor entity telemetry for 48 hours."
            )
            next_steps = [
                "Open Response Center tab to trigger safe simulated containment.",
                "Generate Forensic Incident Dossier PDF for executive escalation."
            ]

        else:
            answer = (
                f"Regarding incident {incident.id}: Total {len(alerts)} alerts aggregated. "
                f"Adversary activity detected: {attack_types[0] if attack_types else 'Generic Attack'}. "
                f"Affected user: {', '.join(usernames) if usernames else 'N/A'}. "
                f"Source IP: {', '.join(source_ips) if source_ips else 'N/A'}."
            )
            next_steps = [
                "Ask 'What happened?', 'Why is the risk high?', or 'What should the analyst investigate next?'."
            ]

        return {
            "incident_id": incident_id,
            "question": question,
            "answer": answer,
            "mitre_technique": f"{mitre_data['technique_id']} - {mitre_data['technique']}",
            "evidence_references": evidence_refs,
            "suggested_next_steps": next_steps,
        }

assistant_engine = LocalInvestigationAssistant()
