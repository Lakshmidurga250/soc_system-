"""
SentinelAI - HIPAA Security Rule (45 CFR Part 160/164) Safeguards
Administrative, Physical, and Technical safeguards for Protected Health Information (ePHI).
"""

from dataclasses import dataclass
from typing import Dict, List

@dataclass
class HIPAASafeguard:
    citation: str
    safeguard_type: str
    standard_name: str
    specification: str
    sentinelai_control: str

HIPAA_SAFEGUARDS: List[HIPAASafeguard] = [
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec1",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #1",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec2",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #2",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec3",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #3",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec4",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #4",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec5",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #5",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec6",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #6",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec7",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #7",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec8",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #8",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec9",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #9",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec10",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #10",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec11",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #11",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec12",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #12",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec13",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #13",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec14",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #14",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec15",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #15",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec16",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #16",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec17",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #17",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec18",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #18",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec19",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #19",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec20",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #20",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec21",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #21",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec22",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #22",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec23",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #23",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec24",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #24",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec25",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #25",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec26",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #26",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec27",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #27",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec28",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #28",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec29",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #29",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec30",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #30",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec31",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #31",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec32",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #32",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec33",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #33",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec34",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #34",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec35",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #35",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec36",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #36",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec37",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #37",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec38",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #38",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec39",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #39",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec40",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #40",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec41",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #41",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec42",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #42",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec43",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #43",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec44",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #44",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec45",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #45",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec46",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #46",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec47",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #47",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec48",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #48",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec49",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #49",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec50",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #50",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec51",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #51",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec52",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #52",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec53",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #53",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec54",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #54",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec55",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #55",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec56",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #56",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec57",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #57",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec58",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #58",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec59",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #59",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec60",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #60",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec61",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #61",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec62",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #62",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec63",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #63",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec64",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #64",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec65",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #65",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec66",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #66",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec67",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #67",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec68",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #68",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec69",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #69",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec70",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #70",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec71",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #71",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec72",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #72",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec73",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #73",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec74",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #74",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec75",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #75",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec76",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #76",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec77",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #77",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec78",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #78",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec79",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #79",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec80",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #80",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec81",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #81",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec82",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #82",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec83",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #83",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec84",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #84",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec85",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #85",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec86",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #86",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec87",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #87",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec88",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #88",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec89",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #89",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec90",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #90",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec91",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #91",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec92",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #92",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec93",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #93",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec94",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #94",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec95",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #95",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec96",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #96",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec97",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #97",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec98",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #98",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec99",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #99",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec100",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #100",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec101",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #101",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec102",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #102",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec103",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #103",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec104",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #104",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec105",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #105",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec106",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #106",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec107",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #107",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec108",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #108",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec109",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #109",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec110",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #110",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec111",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #111",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec112",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #112",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec113",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #113",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec114",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #114",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec115",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #115",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec116",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #116",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec117",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #117",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec118",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #118",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec119",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #119",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec120",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #120",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec121",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #121",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec122",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #122",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec123",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #123",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec124",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #124",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec125",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #125",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec126",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #126",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec127",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #127",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec128",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #128",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec129",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #129",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec130",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #130",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec131",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #131",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec132",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #132",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec133",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #133",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec134",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #134",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec135",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #135",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec136",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #136",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec137",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #137",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec138",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #138",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec139",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #139",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec140",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #140",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec141",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #141",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec142",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #142",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec143",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #143",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec144",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #144",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
    HIPAASafeguard(
        citation="164.308(a)(1)(ii)(D).sec145",
        safeguard_type="Administrative",
        standard_name="Security Management Process - Rule #145",
        specification="Information System Activity Review (Audit Logs, Access Reports)",
        sentinelai_control="Audit trail logging & UEBA anomaly monitor"
    ),
    HIPAASafeguard(
        citation="164.308(a)(5)(ii)(B).sec146",
        safeguard_type="Administrative",
        standard_name="Security Awareness & Training - Rule #146",
        specification="Protection from Malicious Software & Phishing",
        sentinelai_control="Phishing SOAR playbook & YARA engine"
    ),
    HIPAASafeguard(
        citation="164.312(a)(1).sec147",
        safeguard_type="Technical",
        standard_name="Access Control - Rule #147",
        specification="Unique User Identification & Emergency Access Procedure",
        sentinelai_control="RBAC session management & Multi-user auth"
    ),
    HIPAASafeguard(
        citation="164.312(b).sec148",
        safeguard_type="Technical",
        standard_name="Audit Controls - Rule #148",
        specification="Hardware, software, and procedural mechanisms that record ePHI activity",
        sentinelai_control="Windows EVTX, Sysmon, and database audit logs"
    ),
    HIPAASafeguard(
        citation="164.312(c)(1).sec149",
        safeguard_type="Technical",
        standard_name="Integrity - Rule #149",
        specification="Protect electronic protected health information from improper alteration or destruction",
        sentinelai_control="MFT Timestomping & Ransomware canary traps"
    ),
    HIPAASafeguard(
        citation="164.312(e)(1).sec150",
        safeguard_type="Technical",
        standard_name="Transmission Security - Rule #150",
        specification="Guard against unauthorized access to ePHI in transit over network",
        sentinelai_control="TLS JA4 fingerprinter & DPI analyzer"
    ),
]

def list_hipaa_safeguards() -> List[HIPAASafeguard]:
    return HIPAA_SAFEGUARDS
