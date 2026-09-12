"""
SentinelAI - Multi-Artifact Forensic Evidence Extraction & Timeline Correlator
Parses Windows Prefetch, ShimCache, Amcache, Linux Auditd, and MacOS Launchd artifacts.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import datetime
import hashlib
import re

class ForensicArtifactType(Enum):
    PREFETCH = "PREFETCH"
    SHIMCACHE = "SHIMCACHE"
    AMCACHE = "AMCACHE"
    MFT_ENTRY = "MFT_ENTRY"
    SYSTEMD_JOURNAL = "SYSTEMD_JOURNAL"
    AUDITD_RECORD = "AUDITD_RECORD"
    BASH_HISTORY = "BASH_HISTORY"
    MACOS_UNIFIED_LOG = "MACOS_UNIFIED_LOG"

@dataclass
class ForensicEvidenceItem:
    evidence_id: str
    artifact_type: ForensicArtifactType
    source_host: str
    timestamp: str
    executable_path: str
    process_id: Optional[int] = None
    user_context: Optional[str] = None
    sha256: Optional[str] = None
    execution_count: int = 1
    raw_attributes: Dict[str, Any] = field(default_factory=dict)
    is_suspicious: bool = False
    mitre_technique: Optional[str] = None

class ForensicsCorrelationPipeline:
    def __init__(self):
        self.evidence_store: List[ForensicEvidenceItem] = []
        self.known_bad_hashes: Set[str] = {
            "44d88612fea8a8f36de82e1278abb02f",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        }
        self.lolbins: Set[str] = {
            "certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
            "bitsadmin.exe", "powershell.exe", "wmic.exe", "curl.exe"
        }

    def ingest_evidence(self, item: ForensicEvidenceItem) -> Dict[str, Any]:
        exe_lower = item.executable_path.lower()
        if any(item.executable_path.lower().endswith(lb) for lb in self.lolbins):
            item.is_suspicious = True
            item.mitre_technique = "T1218 - System Binary Proxy Execution"
            
        if item.sha256 and item.sha256.lower() in self.known_bad_hashes:
            item.is_suspicious = True
            item.mitre_technique = "T1059 - Command and Scripting Interpreter"
            
        self.evidence_store.append(item)
        return {
            "evidence_id": item.evidence_id,
            "status": "INGESTED",
            "is_suspicious": item.is_suspicious,
            "mitre_technique": item.mitre_technique
        }

    def construct_chronological_timeline(self, host_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        filtered = self.evidence_store
        if host_filter:
            filtered = [e for e in filtered if e.source_host == host_filter]
        sorted_ev = sorted(filtered, key=lambda x: x.timestamp)
        return [
            {
                "time": ev.timestamp,
                "host": ev.source_host,
                "type": ev.artifact_type.value,
                "executable": ev.executable_path,
                "suspicious": ev.is_suspicious,
                "technique": ev.mitre_technique
            }
            for ev in sorted_ev
        ]

forensic_pipeline = ForensicsCorrelationPipeline()
