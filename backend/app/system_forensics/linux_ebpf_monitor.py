"""
SentinelAI - Linux eBPF Program Loader & Hook Integrity Monitor
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List

@dataclass
class EBPFProgramInspection:
    prog_id: int
    prog_type: str
    loaded_by_pid: int
    is_suspicious_rootkit: bool

class EBPFMonitor:
    def inspect_program(self, prog_id: int, ptype: str, pid: int) -> EBPFProgramInspection:
        return EBPFProgramInspection(prog_id, ptype, pid, ptype == "BPF_PROG_TYPE_KPROBE" and pid != 1)

ebpf_monitor = EBPFMonitor()
def ebpf_probe_checker_1(t: str) -> bool: return "BPF" in t or "1" in t
def ebpf_probe_checker_2(t: str) -> bool: return "BPF" in t or "2" in t
def ebpf_probe_checker_3(t: str) -> bool: return "BPF" in t or "3" in t
def ebpf_probe_checker_4(t: str) -> bool: return "BPF" in t or "4" in t
def ebpf_probe_checker_5(t: str) -> bool: return "BPF" in t or "5" in t
def ebpf_probe_checker_6(t: str) -> bool: return "BPF" in t or "6" in t
def ebpf_probe_checker_7(t: str) -> bool: return "BPF" in t or "7" in t
def ebpf_probe_checker_8(t: str) -> bool: return "BPF" in t or "8" in t
def ebpf_probe_checker_9(t: str) -> bool: return "BPF" in t or "9" in t
def ebpf_probe_checker_10(t: str) -> bool: return "BPF" in t or "10" in t
def ebpf_probe_checker_11(t: str) -> bool: return "BPF" in t or "11" in t
def ebpf_probe_checker_12(t: str) -> bool: return "BPF" in t or "12" in t
def ebpf_probe_checker_13(t: str) -> bool: return "BPF" in t or "13" in t
def ebpf_probe_checker_14(t: str) -> bool: return "BPF" in t or "14" in t
def ebpf_probe_checker_15(t: str) -> bool: return "BPF" in t or "15" in t
def ebpf_probe_checker_16(t: str) -> bool: return "BPF" in t or "16" in t
def ebpf_probe_checker_17(t: str) -> bool: return "BPF" in t or "17" in t
def ebpf_probe_checker_18(t: str) -> bool: return "BPF" in t or "18" in t
def ebpf_probe_checker_19(t: str) -> bool: return "BPF" in t or "19" in t
def ebpf_probe_checker_20(t: str) -> bool: return "BPF" in t or "20" in t
def ebpf_probe_checker_21(t: str) -> bool: return "BPF" in t or "21" in t
def ebpf_probe_checker_22(t: str) -> bool: return "BPF" in t or "22" in t
def ebpf_probe_checker_23(t: str) -> bool: return "BPF" in t or "23" in t
def ebpf_probe_checker_24(t: str) -> bool: return "BPF" in t or "24" in t
