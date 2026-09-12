"""
SentinelAI - Automated Phishing Email Triage & Mailbox Remediation Playbook
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class PhishingTriageAction:
    step_id: str
    name: str
    phase: str
    description: str
    dry_run_syntax: str

PHISHING_PLAYBOOK_STEPS: List[PhishingTriageAction] = [
    PhishingTriageAction(
        step_id="PHISH-01-1",
        name="SPF/DKIM/DMARC Authentication Verification (Step 1)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-2",
        name="URL Sandboxing & Screenshot Capture (Step 2)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-3",
        name="Attachment Hash Lookup & YARA Scan (Step 3)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-4",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 4)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-5",
        name="Reset Compromised User Password & Terminate Sessions (Step 5)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-6",
        name="SPF/DKIM/DMARC Authentication Verification (Step 6)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-7",
        name="URL Sandboxing & Screenshot Capture (Step 7)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-8",
        name="Attachment Hash Lookup & YARA Scan (Step 8)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-9",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 9)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-10",
        name="Reset Compromised User Password & Terminate Sessions (Step 10)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-11",
        name="SPF/DKIM/DMARC Authentication Verification (Step 11)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-12",
        name="URL Sandboxing & Screenshot Capture (Step 12)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-13",
        name="Attachment Hash Lookup & YARA Scan (Step 13)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-14",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 14)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-15",
        name="Reset Compromised User Password & Terminate Sessions (Step 15)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-16",
        name="SPF/DKIM/DMARC Authentication Verification (Step 16)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-17",
        name="URL Sandboxing & Screenshot Capture (Step 17)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-18",
        name="Attachment Hash Lookup & YARA Scan (Step 18)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-19",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 19)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-20",
        name="Reset Compromised User Password & Terminate Sessions (Step 20)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-21",
        name="SPF/DKIM/DMARC Authentication Verification (Step 21)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-22",
        name="URL Sandboxing & Screenshot Capture (Step 22)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-23",
        name="Attachment Hash Lookup & YARA Scan (Step 23)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-24",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 24)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-25",
        name="Reset Compromised User Password & Terminate Sessions (Step 25)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-26",
        name="SPF/DKIM/DMARC Authentication Verification (Step 26)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-27",
        name="URL Sandboxing & Screenshot Capture (Step 27)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-28",
        name="Attachment Hash Lookup & YARA Scan (Step 28)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-29",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 29)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-30",
        name="Reset Compromised User Password & Terminate Sessions (Step 30)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-31",
        name="SPF/DKIM/DMARC Authentication Verification (Step 31)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-32",
        name="URL Sandboxing & Screenshot Capture (Step 32)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-33",
        name="Attachment Hash Lookup & YARA Scan (Step 33)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-34",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 34)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-35",
        name="Reset Compromised User Password & Terminate Sessions (Step 35)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-36",
        name="SPF/DKIM/DMARC Authentication Verification (Step 36)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-37",
        name="URL Sandboxing & Screenshot Capture (Step 37)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-38",
        name="Attachment Hash Lookup & YARA Scan (Step 38)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-39",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 39)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-40",
        name="Reset Compromised User Password & Terminate Sessions (Step 40)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-41",
        name="SPF/DKIM/DMARC Authentication Verification (Step 41)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-42",
        name="URL Sandboxing & Screenshot Capture (Step 42)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-43",
        name="Attachment Hash Lookup & YARA Scan (Step 43)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-44",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 44)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-45",
        name="Reset Compromised User Password & Terminate Sessions (Step 45)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-46",
        name="SPF/DKIM/DMARC Authentication Verification (Step 46)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-47",
        name="URL Sandboxing & Screenshot Capture (Step 47)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-48",
        name="Attachment Hash Lookup & YARA Scan (Step 48)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-49",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 49)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-50",
        name="Reset Compromised User Password & Terminate Sessions (Step 50)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-51",
        name="SPF/DKIM/DMARC Authentication Verification (Step 51)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-52",
        name="URL Sandboxing & Screenshot Capture (Step 52)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-53",
        name="Attachment Hash Lookup & YARA Scan (Step 53)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-54",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 54)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-55",
        name="Reset Compromised User Password & Terminate Sessions (Step 55)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-56",
        name="SPF/DKIM/DMARC Authentication Verification (Step 56)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-57",
        name="URL Sandboxing & Screenshot Capture (Step 57)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-58",
        name="Attachment Hash Lookup & YARA Scan (Step 58)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-59",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 59)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-60",
        name="Reset Compromised User Password & Terminate Sessions (Step 60)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-61",
        name="SPF/DKIM/DMARC Authentication Verification (Step 61)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-62",
        name="URL Sandboxing & Screenshot Capture (Step 62)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-63",
        name="Attachment Hash Lookup & YARA Scan (Step 63)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-64",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 64)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-65",
        name="Reset Compromised User Password & Terminate Sessions (Step 65)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-66",
        name="SPF/DKIM/DMARC Authentication Verification (Step 66)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-67",
        name="URL Sandboxing & Screenshot Capture (Step 67)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-68",
        name="Attachment Hash Lookup & YARA Scan (Step 68)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-69",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 69)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-70",
        name="Reset Compromised User Password & Terminate Sessions (Step 70)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-71",
        name="SPF/DKIM/DMARC Authentication Verification (Step 71)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-72",
        name="URL Sandboxing & Screenshot Capture (Step 72)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-73",
        name="Attachment Hash Lookup & YARA Scan (Step 73)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-74",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 74)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-75",
        name="Reset Compromised User Password & Terminate Sessions (Step 75)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-76",
        name="SPF/DKIM/DMARC Authentication Verification (Step 76)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-77",
        name="URL Sandboxing & Screenshot Capture (Step 77)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-78",
        name="Attachment Hash Lookup & YARA Scan (Step 78)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-79",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 79)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-80",
        name="Reset Compromised User Password & Terminate Sessions (Step 80)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-81",
        name="SPF/DKIM/DMARC Authentication Verification (Step 81)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-82",
        name="URL Sandboxing & Screenshot Capture (Step 82)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-83",
        name="Attachment Hash Lookup & YARA Scan (Step 83)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-84",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 84)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-85",
        name="Reset Compromised User Password & Terminate Sessions (Step 85)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-86",
        name="SPF/DKIM/DMARC Authentication Verification (Step 86)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-87",
        name="URL Sandboxing & Screenshot Capture (Step 87)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-88",
        name="Attachment Hash Lookup & YARA Scan (Step 88)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-89",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 89)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-90",
        name="Reset Compromised User Password & Terminate Sessions (Step 90)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-91",
        name="SPF/DKIM/DMARC Authentication Verification (Step 91)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-92",
        name="URL Sandboxing & Screenshot Capture (Step 92)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-93",
        name="Attachment Hash Lookup & YARA Scan (Step 93)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-94",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 94)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-95",
        name="Reset Compromised User Password & Terminate Sessions (Step 95)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
    PhishingTriageAction(
        step_id="PHISH-01-96",
        name="SPF/DKIM/DMARC Authentication Verification (Step 96)",
        phase="TRIAGE",
        description="Validate SPF pass, DKIM signature alignment, and DMARC enforcement.",
        dry_run_syntax="verify_email_headers --dmarc enforce"
    ),
    PhishingTriageAction(
        step_id="PHISH-02-97",
        name="URL Sandboxing & Screenshot Capture (Step 97)",
        phase="INVESTIGATION",
        description="Submit embedded URLs to safe headless browser sandbox and extract DOM.",
        dry_run_syntax="sandbox_url --headless --screenshot"
    ),
    PhishingTriageAction(
        step_id="PHISH-03-98",
        name="Attachment Hash Lookup & YARA Scan (Step 98)",
        phase="ANALYSIS",
        description="Calculate SHA256 of attached files and scan with YARA malware engine.",
        dry_run_syntax="scan_attachment --yara-all"
    ),
    PhishingTriageAction(
        step_id="PHISH-04-99",
        name="Global Mailbox Search & Purge (Exchange/O365) (Step 99)",
        phase="CONTAINMENT",
        description="Query message trace across entire tenant and soft-delete matching messages.",
        dry_run_syntax="New-ComplianceSearchAction -Purge -PurgeType SoftDelete"
    ),
    PhishingTriageAction(
        step_id="PHISH-05-100",
        name="Reset Compromised User Password & Terminate Sessions (Step 100)",
        phase="REMEDIATION",
        description="Force immediate password reset and revoke OAuth refresh tokens.",
        dry_run_syntax="Revoke-AzureADUserAllRefreshToken -ObjectId {user_id}"
    ),
]
def get_phishing_playbook() -> List[PhishingTriageAction]: return PHISHING_PLAYBOOK_STEPS
