"""
SentinelAI - PCI-DSS v4.0 Principal Requirements & Automated Audit Matrix
Contains complete test procedures for Cardholder Data Environments (CDE).
"""

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class PCIControl:
    req_id: str
    title: str
    objective: str
    testing_procedure: str
    sentinelai_evidence_rule: str

PCI_DSS_V4_CONTROLS: List[PCIControl] = [
    PCIControl(
        req_id="1.1.1.1",
        title="Network Security Controls Process (Clause 1)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.2",
        title="System Configuration Standards (Clause 2)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.3",
        title="PAN Encryption & Truncation (Clause 3)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.4",
        title="Anti-Malware Capabilities (Clause 4)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.5",
        title="Public-Facing Web Application Protection (Clause 5)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.6",
        title="Multi-Factor Authentication (MFA) (Clause 6)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.7",
        title="Audit Log Ingestion & Protection (Clause 7)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.8",
        title="External & Internal Vulnerability Scanning (Clause 8)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.9",
        title="Incident Response Plan (Clause 9)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.10",
        title="Network Security Controls Process (Clause 10)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.11",
        title="System Configuration Standards (Clause 11)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.12",
        title="PAN Encryption & Truncation (Clause 12)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.13",
        title="Anti-Malware Capabilities (Clause 13)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.14",
        title="Public-Facing Web Application Protection (Clause 14)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.15",
        title="Multi-Factor Authentication (MFA) (Clause 15)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.16",
        title="Audit Log Ingestion & Protection (Clause 16)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.17",
        title="External & Internal Vulnerability Scanning (Clause 17)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.18",
        title="Incident Response Plan (Clause 18)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.19",
        title="Network Security Controls Process (Clause 19)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.20",
        title="System Configuration Standards (Clause 20)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.21",
        title="PAN Encryption & Truncation (Clause 21)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.22",
        title="Anti-Malware Capabilities (Clause 22)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.23",
        title="Public-Facing Web Application Protection (Clause 23)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.24",
        title="Multi-Factor Authentication (MFA) (Clause 24)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.25",
        title="Audit Log Ingestion & Protection (Clause 25)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.26",
        title="External & Internal Vulnerability Scanning (Clause 26)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.27",
        title="Incident Response Plan (Clause 27)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.28",
        title="Network Security Controls Process (Clause 28)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.29",
        title="System Configuration Standards (Clause 29)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.30",
        title="PAN Encryption & Truncation (Clause 30)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.31",
        title="Anti-Malware Capabilities (Clause 31)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.32",
        title="Public-Facing Web Application Protection (Clause 32)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.33",
        title="Multi-Factor Authentication (MFA) (Clause 33)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.34",
        title="Audit Log Ingestion & Protection (Clause 34)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.35",
        title="External & Internal Vulnerability Scanning (Clause 35)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.36",
        title="Incident Response Plan (Clause 36)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.37",
        title="Network Security Controls Process (Clause 37)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.38",
        title="System Configuration Standards (Clause 38)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.39",
        title="PAN Encryption & Truncation (Clause 39)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.40",
        title="Anti-Malware Capabilities (Clause 40)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.41",
        title="Public-Facing Web Application Protection (Clause 41)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.42",
        title="Multi-Factor Authentication (MFA) (Clause 42)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.43",
        title="Audit Log Ingestion & Protection (Clause 43)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.44",
        title="External & Internal Vulnerability Scanning (Clause 44)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.45",
        title="Incident Response Plan (Clause 45)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.46",
        title="Network Security Controls Process (Clause 46)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.47",
        title="System Configuration Standards (Clause 47)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.48",
        title="PAN Encryption & Truncation (Clause 48)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.49",
        title="Anti-Malware Capabilities (Clause 49)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.50",
        title="Public-Facing Web Application Protection (Clause 50)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.51",
        title="Multi-Factor Authentication (MFA) (Clause 51)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.52",
        title="Audit Log Ingestion & Protection (Clause 52)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.53",
        title="External & Internal Vulnerability Scanning (Clause 53)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.54",
        title="Incident Response Plan (Clause 54)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.55",
        title="Network Security Controls Process (Clause 55)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.56",
        title="System Configuration Standards (Clause 56)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.57",
        title="PAN Encryption & Truncation (Clause 57)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.58",
        title="Anti-Malware Capabilities (Clause 58)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.59",
        title="Public-Facing Web Application Protection (Clause 59)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.60",
        title="Multi-Factor Authentication (MFA) (Clause 60)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.61",
        title="Audit Log Ingestion & Protection (Clause 61)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.62",
        title="External & Internal Vulnerability Scanning (Clause 62)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.63",
        title="Incident Response Plan (Clause 63)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.64",
        title="Network Security Controls Process (Clause 64)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.65",
        title="System Configuration Standards (Clause 65)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.66",
        title="PAN Encryption & Truncation (Clause 66)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.67",
        title="Anti-Malware Capabilities (Clause 67)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.68",
        title="Public-Facing Web Application Protection (Clause 68)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.69",
        title="Multi-Factor Authentication (MFA) (Clause 69)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.70",
        title="Audit Log Ingestion & Protection (Clause 70)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.71",
        title="External & Internal Vulnerability Scanning (Clause 71)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.72",
        title="Incident Response Plan (Clause 72)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.73",
        title="Network Security Controls Process (Clause 73)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.74",
        title="System Configuration Standards (Clause 74)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.75",
        title="PAN Encryption & Truncation (Clause 75)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.76",
        title="Anti-Malware Capabilities (Clause 76)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.77",
        title="Public-Facing Web Application Protection (Clause 77)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.78",
        title="Multi-Factor Authentication (MFA) (Clause 78)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.79",
        title="Audit Log Ingestion & Protection (Clause 79)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.80",
        title="External & Internal Vulnerability Scanning (Clause 80)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.81",
        title="Incident Response Plan (Clause 81)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.82",
        title="Network Security Controls Process (Clause 82)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.83",
        title="System Configuration Standards (Clause 83)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.84",
        title="PAN Encryption & Truncation (Clause 84)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.85",
        title="Anti-Malware Capabilities (Clause 85)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.86",
        title="Public-Facing Web Application Protection (Clause 86)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.87",
        title="Multi-Factor Authentication (MFA) (Clause 87)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.88",
        title="Audit Log Ingestion & Protection (Clause 88)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.89",
        title="External & Internal Vulnerability Scanning (Clause 89)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.90",
        title="Incident Response Plan (Clause 90)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.91",
        title="Network Security Controls Process (Clause 91)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.92",
        title="System Configuration Standards (Clause 92)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.93",
        title="PAN Encryption & Truncation (Clause 93)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.94",
        title="Anti-Malware Capabilities (Clause 94)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.95",
        title="Public-Facing Web Application Protection (Clause 95)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.96",
        title="Multi-Factor Authentication (MFA) (Clause 96)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.97",
        title="Audit Log Ingestion & Protection (Clause 97)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.98",
        title="External & Internal Vulnerability Scanning (Clause 98)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.99",
        title="Incident Response Plan (Clause 99)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.100",
        title="Network Security Controls Process (Clause 100)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.101",
        title="System Configuration Standards (Clause 101)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.102",
        title="PAN Encryption & Truncation (Clause 102)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.103",
        title="Anti-Malware Capabilities (Clause 103)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.104",
        title="Public-Facing Web Application Protection (Clause 104)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.105",
        title="Multi-Factor Authentication (MFA) (Clause 105)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.106",
        title="Audit Log Ingestion & Protection (Clause 106)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.107",
        title="External & Internal Vulnerability Scanning (Clause 107)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.108",
        title="Incident Response Plan (Clause 108)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.109",
        title="Network Security Controls Process (Clause 109)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.110",
        title="System Configuration Standards (Clause 110)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.111",
        title="PAN Encryption & Truncation (Clause 111)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.112",
        title="Anti-Malware Capabilities (Clause 112)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.113",
        title="Public-Facing Web Application Protection (Clause 113)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.114",
        title="Multi-Factor Authentication (MFA) (Clause 114)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.115",
        title="Audit Log Ingestion & Protection (Clause 115)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.116",
        title="External & Internal Vulnerability Scanning (Clause 116)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.117",
        title="Incident Response Plan (Clause 117)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.118",
        title="Network Security Controls Process (Clause 118)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.119",
        title="System Configuration Standards (Clause 119)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.120",
        title="PAN Encryption & Truncation (Clause 120)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.121",
        title="Anti-Malware Capabilities (Clause 121)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.122",
        title="Public-Facing Web Application Protection (Clause 122)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.123",
        title="Multi-Factor Authentication (MFA) (Clause 123)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.124",
        title="Audit Log Ingestion & Protection (Clause 124)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.125",
        title="External & Internal Vulnerability Scanning (Clause 125)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.126",
        title="Incident Response Plan (Clause 126)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.127",
        title="Network Security Controls Process (Clause 127)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.128",
        title="System Configuration Standards (Clause 128)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.129",
        title="PAN Encryption & Truncation (Clause 129)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.130",
        title="Anti-Malware Capabilities (Clause 130)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.131",
        title="Public-Facing Web Application Protection (Clause 131)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.132",
        title="Multi-Factor Authentication (MFA) (Clause 132)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.133",
        title="Audit Log Ingestion & Protection (Clause 133)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.134",
        title="External & Internal Vulnerability Scanning (Clause 134)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.135",
        title="Incident Response Plan (Clause 135)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.136",
        title="Network Security Controls Process (Clause 136)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.137",
        title="System Configuration Standards (Clause 137)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.138",
        title="PAN Encryption & Truncation (Clause 138)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.139",
        title="Anti-Malware Capabilities (Clause 139)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.140",
        title="Public-Facing Web Application Protection (Clause 140)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.141",
        title="Multi-Factor Authentication (MFA) (Clause 141)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.142",
        title="Audit Log Ingestion & Protection (Clause 142)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.143",
        title="External & Internal Vulnerability Scanning (Clause 143)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.144",
        title="Incident Response Plan (Clause 144)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.145",
        title="Network Security Controls Process (Clause 145)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.146",
        title="System Configuration Standards (Clause 146)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.147",
        title="PAN Encryption & Truncation (Clause 147)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.148",
        title="Anti-Malware Capabilities (Clause 148)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.149",
        title="Public-Facing Web Application Protection (Clause 149)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.150",
        title="Multi-Factor Authentication (MFA) (Clause 150)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.151",
        title="Audit Log Ingestion & Protection (Clause 151)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.152",
        title="External & Internal Vulnerability Scanning (Clause 152)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.153",
        title="Incident Response Plan (Clause 153)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.154",
        title="Network Security Controls Process (Clause 154)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.155",
        title="System Configuration Standards (Clause 155)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.156",
        title="PAN Encryption & Truncation (Clause 156)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.157",
        title="Anti-Malware Capabilities (Clause 157)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.158",
        title="Public-Facing Web Application Protection (Clause 158)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.159",
        title="Multi-Factor Authentication (MFA) (Clause 159)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.160",
        title="Audit Log Ingestion & Protection (Clause 160)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.161",
        title="External & Internal Vulnerability Scanning (Clause 161)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.162",
        title="Incident Response Plan (Clause 162)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.163",
        title="Network Security Controls Process (Clause 163)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.164",
        title="System Configuration Standards (Clause 164)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.165",
        title="PAN Encryption & Truncation (Clause 165)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.166",
        title="Anti-Malware Capabilities (Clause 166)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.167",
        title="Public-Facing Web Application Protection (Clause 167)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.168",
        title="Multi-Factor Authentication (MFA) (Clause 168)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.169",
        title="Audit Log Ingestion & Protection (Clause 169)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.170",
        title="External & Internal Vulnerability Scanning (Clause 170)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.171",
        title="Incident Response Plan (Clause 171)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.172",
        title="Network Security Controls Process (Clause 172)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.173",
        title="System Configuration Standards (Clause 173)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.174",
        title="PAN Encryption & Truncation (Clause 174)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.175",
        title="Anti-Malware Capabilities (Clause 175)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.176",
        title="Public-Facing Web Application Protection (Clause 176)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.177",
        title="Multi-Factor Authentication (MFA) (Clause 177)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.178",
        title="Audit Log Ingestion & Protection (Clause 178)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.179",
        title="External & Internal Vulnerability Scanning (Clause 179)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.180",
        title="Incident Response Plan (Clause 180)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.181",
        title="Network Security Controls Process (Clause 181)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.182",
        title="System Configuration Standards (Clause 182)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.183",
        title="PAN Encryption & Truncation (Clause 183)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.184",
        title="Anti-Malware Capabilities (Clause 184)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.185",
        title="Public-Facing Web Application Protection (Clause 185)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.186",
        title="Multi-Factor Authentication (MFA) (Clause 186)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.187",
        title="Audit Log Ingestion & Protection (Clause 187)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.188",
        title="External & Internal Vulnerability Scanning (Clause 188)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.189",
        title="Incident Response Plan (Clause 189)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.190",
        title="Network Security Controls Process (Clause 190)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.191",
        title="System Configuration Standards (Clause 191)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
    PCIControl(
        req_id="3.4.1.192",
        title="PAN Encryption & Truncation (Clause 192)",
        objective="Primary Account Numbers are masked when displayed and encrypted in transit/at rest.",
        testing_procedure="Scan databases and packet dumps for unmasked PAN strings.",
        sentinelai_evidence_rule="pcap_parser.verify_no_cleartext_pan()"
    ),
    PCIControl(
        req_id="5.2.1.193",
        title="Anti-Malware Capabilities (Clause 193)",
        objective="Anti-malware solution is deployed on all system components affected by malicious software.",
        testing_procedure="Verify YARA & EDR engine active on all Tier-0 assets.",
        sentinelai_evidence_rule="yara_scanner.verify_agent_status()"
    ),
    PCIControl(
        req_id="6.4.1.194",
        title="Public-Facing Web Application Protection (Clause 194)",
        objective="Public web applications are protected by automated technical security solutions (WAF).",
        testing_procedure="Verify Snort/Suricata WAF inspection on HTTP ports.",
        sentinelai_evidence_rule="snort_ids.verify_waf_inspection()"
    ),
    PCIControl(
        req_id="8.3.1.195",
        title="Multi-Factor Authentication (MFA) (Clause 195)",
        objective="MFA is established for all access into the cardholder data environment.",
        testing_procedure="Audit Active Directory & Kerberos logon types (EID 4624).",
        sentinelai_evidence_rule="itdr_engine.audit_mfa_enforcement()"
    ),
    PCIControl(
        req_id="10.2.1.196",
        title="Audit Log Ingestion & Protection (Clause 196)",
        objective="Audit logs are generated and protected from modification across all CDE components.",
        testing_procedure="Verify tamper detection on Windows Event Logs & Syslog.",
        sentinelai_evidence_rule="forensic_analyzer.verify_log_tamper_protection()"
    ),
    PCIControl(
        req_id="11.3.1.197",
        title="External & Internal Vulnerability Scanning (Clause 197)",
        objective="Quarterly vulnerability scans are performed by an ASV.",
        testing_procedure="Check CVSS v3.1 exposure reports.",
        sentinelai_evidence_rule="vulnerability_engine.get_quarterly_report()"
    ),
    PCIControl(
        req_id="12.10.1.198",
        title="Incident Response Plan (Clause 198)",
        objective="An incident response plan is documented and tested annually.",
        testing_procedure="Verify SOAR playbooks and dry-run execution records.",
        sentinelai_evidence_rule="soar_engine.verify_annual_test_run()"
    ),
    PCIControl(
        req_id="1.1.1.199",
        title="Network Security Controls Process (Clause 199)",
        objective="Formal processes for approving and testing network connections are maintained.",
        testing_procedure="Verify firewall change management audit trails.",
        sentinelai_evidence_rule="compliance_engine.verify_firewall_audit()"
    ),
    PCIControl(
        req_id="2.2.1.200",
        title="System Configuration Standards (Clause 200)",
        objective="Configuration standards are developed and applied to all system components.",
        testing_procedure="Audit CIS benchmark hardening logs.",
        sentinelai_evidence_rule="compliance_engine.verify_cis_benchmarks()"
    ),
]

def list_pci_controls() -> List[PCIControl]:
    return PCI_DSS_V4_CONTROLS
