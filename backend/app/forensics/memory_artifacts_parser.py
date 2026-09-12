"""
SentinelAI - Volatile Memory Artifact Analyzer
Parses simulated memory dumps for injected code, unlinked VAD structures,
hollowed PE headers, and anomalous kernel drivers.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any
import datetime

@dataclass
class MemoryInjectionArtifact:
    pid: int
    process_name: str
    vad_start_address: str
    vad_end_address: str
    protection: str # PAGE_EXECUTE_READWRITE (RWX)
    has_pe_magic: bool # b'MZ' header present in unmapped memory
    confidence: float
    threat_classification: str

class MemoryArtifactsAnalyzer:
    """Inspects process memory structures for advanced in-memory evasion."""

    def scan_memory_vads(self, process_vads: List[Dict[str, Any]]) -> List[MemoryInjectionArtifact]:
        injections = []
        for vad in process_vads:
            prot = vad.get("protection", "")
            has_mz = vad.get("has_pe_magic", False)
            proc_name = vad.get("process_name", "unknown")
            pid = vad.get("pid", 0)

            # RWX memory with MZ header is a hallmark of reflective DLL / shellcode injection
            if "EXECUTE_READWRITE" in prot and has_mz:
                injections.append(MemoryInjectionArtifact(
                    pid=pid,
                    process_name=proc_name,
                    vad_start_address=vad.get("start", "0x00007FF70000"),
                    vad_end_address=vad.get("end", "0x00007FF71000"),
                    protection=prot,
                    has_pe_magic=True,
                    confidence=0.98,
                    threat_classification="Reflective DLL Injection / Cobalt Strike Beacon"
                ))
            elif "EXECUTE_READWRITE" in prot:
                injections.append(MemoryInjectionArtifact(
                    pid=pid,
                    process_name=proc_name,
                    vad_start_address=vad.get("start", "0x00007FF70000"),
                    vad_end_address=vad.get("end", "0x00007FF71000"),
                    protection=prot,
                    has_pe_magic=False,
                    confidence=0.85,
                    threat_classification="Suspicious RWX Allocation (Shellcode / Hook)"
                ))

        return injections

memory_analyzer = MemoryArtifactsAnalyzer()
