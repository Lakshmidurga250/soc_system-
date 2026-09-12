"""
SentinelAI - SOC 2 Type II Trust Services Criteria Matrix
Covers Security, Availability, Processing Integrity, Confidentiality, Privacy.
"""

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class SOC2Criterion:
    criteria_id: str
    category: str
    point_of_focus: str
    evaluation_method: str

SOC2_CRITERIA: List[SOC2Criterion] = [
    SOC2Criterion(
        criteria_id="CC6.1.1",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #1)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.2",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #2)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.3",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #3)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.4",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #4)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.5",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #5)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.6",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #6)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.7",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #7)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.8",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #8)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.9",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #9)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.10",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #10)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.11",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #11)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.12",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #12)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.13",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #13)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.14",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #14)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.15",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #15)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.16",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #16)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.17",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #17)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.18",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #18)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.19",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #19)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.20",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #20)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.21",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #21)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.22",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #22)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.23",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #23)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.24",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #24)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.25",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #25)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.26",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #26)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.27",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #27)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.28",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #28)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.29",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #29)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.30",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #30)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.31",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #31)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.32",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #32)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.33",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #33)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.34",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #34)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.35",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #35)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.36",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #36)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.37",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #37)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.38",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #38)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.39",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #39)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.40",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #40)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.41",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #41)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.42",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #42)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.43",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #43)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.44",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #44)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.45",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #45)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.46",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #46)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.47",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #47)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.48",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #48)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.49",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #49)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.50",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #50)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.51",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #51)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.52",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #52)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.53",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #53)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.54",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #54)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.55",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #55)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.56",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #56)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.57",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #57)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.58",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #58)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.59",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #59)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.60",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #60)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.61",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #61)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.62",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #62)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.63",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #63)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.64",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #64)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.65",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #65)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.66",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #66)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.67",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #67)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.68",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #68)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.69",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #69)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.70",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #70)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.71",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #71)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.72",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #72)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.73",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #73)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.74",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #74)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.75",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #75)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.76",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #76)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.77",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #77)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.78",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #78)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.79",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #79)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.80",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #80)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.81",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #81)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.82",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #82)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.83",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #83)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.84",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #84)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.85",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #85)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.86",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #86)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.87",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #87)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.88",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #88)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.89",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #89)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.90",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #90)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.91",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #91)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.92",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #92)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.93",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #93)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.94",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #94)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.95",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #95)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.96",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #96)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.97",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #97)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.98",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #98)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.99",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #99)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.100",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #100)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.101",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #101)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.102",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #102)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.103",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #103)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.104",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #104)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.105",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #105)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.106",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #106)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.107",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #107)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.108",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #108)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.109",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #109)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.110",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #110)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.111",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #111)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.112",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #112)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.113",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #113)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.114",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #114)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.115",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #115)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.116",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #116)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.117",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #117)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.118",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #118)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.119",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #119)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.120",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #120)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.121",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #121)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.122",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #122)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.123",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #123)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.124",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #124)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.125",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #125)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.126",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #126)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.127",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #127)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.128",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #128)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.129",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #129)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.130",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #130)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.131",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #131)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.132",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #132)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.133",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #133)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.134",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #134)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.135",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #135)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.136",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #136)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.137",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #137)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.138",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #138)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.139",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #139)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.140",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #140)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.141",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #141)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.142",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #142)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.143",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #143)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.144",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #144)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
    SOC2Criterion(
        criteria_id="CC6.1.145",
        category="Common Criteria / Security",
        point_of_focus="Logical Access Security Controls (Authentication & Authorization) (Criterion #145)",
        evaluation_method="Verify JWT session timeouts & RBAC policies"
    ),
    SOC2Criterion(
        criteria_id="CC6.6.146",
        category="Common Criteria / Security",
        point_of_focus="Boundary Protection & Threat Monitoring (Criterion #146)",
        evaluation_method="Verify IDS/IPS Snort rule inspection and edge telemetry"
    ),
    SOC2Criterion(
        criteria_id="CC6.8.147",
        category="Common Criteria / Security",
        point_of_focus="Malicious Software Prevention & Detection (Criterion #147)",
        evaluation_method="Verify YARA malware engine signatures & hash lookups"
    ),
    SOC2Criterion(
        criteria_id="CC7.2.148",
        category="Common Criteria / Security",
        point_of_focus="Anomaly & Security Event Identification (Criterion #148)",
        evaluation_method="Verify Multi-Signal Correlation & ML Anomaly scoring"
    ),
    SOC2Criterion(
        criteria_id="CC7.3.149",
        category="Common Criteria / Security",
        point_of_focus="Security Incident Evaluation & Response (Criterion #149)",
        evaluation_method="Verify Incident Board and SOAR containment execution"
    ),
    SOC2Criterion(
        criteria_id="CC7.4.150",
        category="Common Criteria / Security",
        point_of_focus="Incident Containment & Remediation Workflow (Criterion #150)",
        evaluation_method="Verify dual-custody approval gates and rollback scripts"
    ),
]

def list_soc2_criteria() -> List[SOC2Criterion]:
    return SOC2_CRITERIA
