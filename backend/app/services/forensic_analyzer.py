"""SentinelAI Forensic Artifacts Analysis Engine.

Analyzes host-level forensic telemetry artifacts offline without external dependencies:
- NTFS Master File Table (MFT) Timestomping Detector ($STANDARD_INFO vs $FILE_NAME mismatch)
- Windows Shimcache (AppCompatCache) Execution Timeline Parser
- Windows Prefetch Binary Execution Counters & Last-Run Timestamps
- Linux Bash History, /etc/cron, and systemd Persistence Unit Analyzer
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class TimestompFinding:
    file_path: str
    standard_info_created: str
    file_name_created: str
    discrepancy_seconds: float
    is_timestomped: bool
    confidence: float
    reason: str


class HostForensicAnalyzer:
    """Performs deep host artifact forensic triage."""

    @classmethod
    def detect_mft_timestomping(
        cls,
        artifacts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Detects timestomping anti-forensics by comparing $STANDARD_INFORMATION ($SI)

        and $FILE_NAME ($FN) creation timestamps in NTFS MFT records.
        Attacker tools modify $SI via SetFileTime Win32 API, but kernel restricts $FN modification.
        """
        findings = []

        for item in artifacts:
            path = item.get("file_path", item.get("target_filename", "unknown"))
            si_created_str = item.get("si_created_time")
            fn_created_str = item.get("fn_created_time")

            if not si_created_str or not fn_created_str:
                continue

            try:
                # Parse ISO timestamps or unix timestamps
                si_dt = cls._parse_ts(si_created_str)
                fn_dt = cls._parse_ts(fn_created_str)

                diff_sec = abs((si_dt - fn_dt).total_seconds())

                # $SI is older than $FN by more than 10 seconds indicates deliberate backdating
                is_stomped = False
                reason = "Timestamps match within normal NTFS delta"
                conf = 0.0

                if si_dt < fn_dt and diff_sec > 60:
                    is_stomped = True
                    conf = min(0.99, 0.70 + (diff_sec / 86400.0) * 0.25)
                    reason = f"$SI created timestamp is {round(diff_sec, 1)}s earlier than $FN creation timestamp (Classic Timestomping signature)"
                elif fn_dt < si_dt and diff_sec > 86400:
                    is_stomped = True
                    conf = 0.75
                    reason = f"Anomalous large timestamp discrepancy ({round(diff_sec/3600, 1)} hours) between MFT attributes"

                findings.append({
                    "file_path": path,
                    "si_created_time": si_created_str,
                    "fn_created_time": fn_created_str,
                    "discrepancy_seconds": round(diff_sec, 2),
                    "is_timestomped": is_stomped,
                    "confidence": round(conf, 2),
                    "reason": reason,
                    "mitre_technique": "T1070.006" if is_stomped else None,
                })
            except Exception:
                continue

        return findings

    @classmethod
    def parse_shimcache_entries(
        cls,
        raw_entries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Parses Windows AppCompatCache (Shimcache) execution order and flags suspicious paths."""
        results = []
        suspicious_keywords = ["temp\\", "tmp\\", "appdata\\", "public\\", "downloads\\", "mimikatz", "procdump", "rubeus", "psexec", "nc.exe"]

        for idx, entry in enumerate(raw_entries):
            path = str(entry.get("path", "")).strip()
            mod_time = entry.get("last_modified", "")
            executed = entry.get("executed", True)

            is_sus = any(kw in path.lower() for kw in suspicious_keywords)

            results.append({
                "sequence_index": idx,
                "file_path": path,
                "last_modified": mod_time,
                "executed_flag": executed,
                "is_suspicious_location": is_sus,
                "indicator_tags": ["SUSPICIOUS_PATH"] if is_sus else [],
            })

        return results

    @classmethod
    def analyze_prefetch_data(
        cls,
        prefetch_entries: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Analyzes Windows Prefetch (.pf) metadata to extract execution run-counts and timestamps."""
        results = []
        for pf in prefetch_entries:
            name = pf.get("executable_name", "UNKNOWN.EXE")
            run_count = int(pf.get("run_count", 1))
            last_run = pf.get("last_run_time", datetime.now(timezone.utc).isoformat())
            hash_code = pf.get("prefetch_hash", "")
            loaded_dlls = pf.get("loaded_dlls", [])

            # Suspicious DLL injection or LOLBin indicators
            has_wsh = any("wscript" in dll.lower() or "cscript" in dll.lower() for dll in loaded_dlls)
            has_crypto = any("crypt32" in dll.lower() or "advapi32" in dll.lower() for dll in loaded_dlls)

            results.append({
                "executable_name": name,
                "run_count": run_count,
                "last_run_time": last_run,
                "prefetch_hash": hash_code,
                "loaded_dll_count": len(loaded_dlls),
                "is_first_time_execution": run_count == 1,
                "has_cryptographic_imports": has_crypto,
                "has_scripting_engine_loaded": has_wsh,
            })

        return results

    @classmethod
    def analyze_linux_persistence_artifacts(
        cls,
        bash_history_lines: List[str],
        cron_entries: List[str],
        systemd_services: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Triage Linux host artifacts for defense evasion, reverse shells, and persistence."""
        suspicious_commands = []
        reverse_shell_pattern = re.compile(r"(nc\s+-[e|c]|bash\s+-i\s+>&|/dev/tcp/|python\s+-c\s+.*socket|perl\s+-e\s+.*socket)", re.I)
        defense_evasion_pattern = re.compile(r"(HISTFILE=/dev/null|unset\s+HISTFILE|kill\s+-9\s+auditd|rm\s+-rf\s+/var/log)", re.I)

        for line in bash_history_lines:
            line_str = line.strip()
            if not line_str:
                continue
            if reverse_shell_pattern.search(line_str):
                suspicious_commands.append({"command": line_str, "type": "REVERSE_SHELL", "mitre": "T1059.004"})
            elif defense_evasion_pattern.search(line_str):
                suspicious_commands.append({"command": line_str, "type": "DEFENSE_EVASION", "mitre": "T1070.003"})

        suspicious_crons = []
        for c in cron_entries:
            c_str = c.strip()
            if not c_str or c_str.startswith("#"):
                continue
            if any(w in c_str.lower() for w in ("curl", "wget", "nc ", "python", "bash -i", "/tmp/")):
                suspicious_crons.append({"cron_line": c_str, "reason": "Executes remote payload or runs from /tmp", "mitre": "T1053.003"})

        suspicious_systemd = []
        for s in systemd_services:
            name = s.get("service_name", "")
            exec_start = s.get("exec_start", "")
            if any(p in exec_start.lower() for p in ("/tmp/", "/dev/shm/", "base64", "curl ", "wget ")):
                suspicious_systemd.append({
                    "service_name": name,
                    "exec_start": exec_start,
                    "reason": "Service executes binary from temporary space or contains download cradle",
                    "mitre": "T1543.002",
                })

        total_findings = len(suspicious_commands) + len(suspicious_crons) + len(suspicious_systemd)
        return {
            "total_suspicious_artifacts": total_findings,
            "host_compromise_likelihood": "HIGH" if total_findings >= 2 else ("MEDIUM" if total_findings == 1 else "LOW"),
            "suspicious_bash_commands": suspicious_commands,
            "suspicious_cron_jobs": suspicious_crons,
            "suspicious_systemd_services": suspicious_systemd,
        }

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        if isinstance(ts_str, (int, float)):
            return datetime.fromtimestamp(ts_str, tz=timezone.utc)
        clean = ts_str.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(clean)
        except ValueError:
            return datetime.strptime(clean, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)


# Global instance
forensic_analyzer = HostForensicAnalyzer()
