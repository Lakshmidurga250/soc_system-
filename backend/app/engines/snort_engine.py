"""SentinelAI Snort & Suricata Network IDS/IPS Rule Compiler and Packet Inspection Engine.

Parses standard Snort/Suricata syntax:
  alert <proto> <src_ip> <src_port> -> <dst_ip> <dst_port> (msg:"..."; content:"..."; nocase; sid:...; classtype:...;)

Evaluates network packet payloads, HTTP URIs, DNS headers, and TCP payload streams
offline against 100% locally compiled signatures.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PacketProtocol(str, Enum):
    IP = "IP"
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    DNS = "DNS"
    TLS = "TLS"


@dataclass
class SnortContentMatch:
    content: bytes
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    is_negated: bool = False
    is_fast_pattern: bool = False


@dataclass
class SnortRule:
    action: str  # alert, drop, pass, reject
    protocol: str
    src_net: str
    src_port: str
    direction: str  # -> or <>
    dst_net: str
    dst_port: str
    msg: str
    sid: int
    rev: int
    classtype: str
    severity: str
    mitre_attack: List[str]
    cve: List[str]
    content_matches: List[SnortContentMatch] = field(default_factory=list)
    pcre_regex: Optional[re.Pattern] = None
    flow: Optional[str] = None

    def match_packet(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        payload: bytes,
    ) -> Optional[Dict[str, Any]]:
        """Evaluates whether a packet matches the Snort rule header and content specifications."""
        # 1. Protocol check
        if self.protocol.upper() != "IP" and self.protocol.upper() != proto.upper():
            return None

        # 2. Port check
        if self.dst_port != "any" and str(dst_port) != self.dst_port:
            return None
        if self.src_port != "any" and str(src_port) != self.src_port:
            return None

        # 3. Content matching
        for cm in self.content_matches:
            target_slice = payload
            if cm.offset is not None:
                start = cm.offset
                end = (start + cm.depth) if cm.depth is not None else len(payload)
                target_slice = payload[start:end]

            if cm.nocase:
                found = cm.content.lower() in target_slice.lower()
            else:
                found = cm.content in target_slice

            if cm.is_negated and found:
                return None
            if not cm.is_negated and not found:
                return None

        # 4. PCRE Regex matching
        if self.pcre_regex:
            if not self.pcre_regex.search(payload):
                return None

        return {
            "sid": self.sid,
            "rev": self.rev,
            "action": self.action.upper(),
            "msg": self.msg,
            "classtype": self.classtype,
            "severity": self.severity,
            "mitre_attack": self.mitre_attack,
            "cve": self.cve,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
        }


class SnortCompiler:
    """Compiles raw Snort/Suricata rule strings into executable AST objects."""

    @classmethod
    def compile_rule_text(cls, raw_rule: str) -> Optional[SnortRule]:
        rule_str = raw_rule.strip()
        if not rule_str or rule_str.startswith("#"):
            return None

        # Syntax: action proto src_ip src_port -> dst_ip dst_port (options)
        m_header = re.match(
            r"^(alert|drop|pass|reject)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+(->|<>)\s+([^\s]+)\s+([^\s]+)\s*\((.*)\)$",
            rule_str,
            re.DOTALL,
        )
        if not m_header:
            return None

        action, proto, src_net, src_port, direction, dst_net, dst_port, options_str = m_header.groups()

        # Parse options
        msg = "IDS Alert"
        sid = 1000001
        rev = 1
        classtype = "misc-attack"
        severity = "MEDIUM"
        mitre: List[str] = []
        cves: List[str] = []
        content_matches: List[SnortContentMatch] = []
        pcre_pattern = None
        flow = None

        # Robust token splitter respecting quoted strings
        opt_tokens = []
        buf = []
        in_q = False
        for ch in options_str:
            if ch == '"':
                in_q = not in_q
                buf.append(ch)
            elif ch == ';' and not in_q:
                opt_tokens.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)

        current_content: Optional[SnortContentMatch] = None

        for tok in opt_tokens:
            tok = tok.strip()
            if not tok:
                continue


            if tok.startswith("msg:"):
                msg = tok[4:].strip(' "')
            elif tok.startswith("sid:"):
                sid = int(tok[4:].strip())
            elif tok.startswith("rev:"):
                rev = int(tok[4:].strip())
            elif tok.startswith("classtype:"):
                classtype = tok[10:].strip(' "')
                if classtype in ("trojan-activity", "exploit-kit", "attempted-admin"):
                    severity = "CRITICAL"
                elif classtype in ("web-application-attack", "shellcode-detect", "attempted-user"):
                    severity = "HIGH"
            elif tok.startswith("reference:cve,"):
                cves.append(tok.split(",")[-1].strip())
            elif tok.startswith("reference:mitre,") or tok.startswith("reference:attack,"):
                mitre.append(tok.split(",")[-1].strip())
            elif tok.startswith("content:"):
                val_str = tok[8:].strip(' "')
                is_neg = val_str.startswith("!")
                if is_neg:
                    val_str = val_str[1:].strip(' "')
                # Parse hex |XX XX| within content
                raw_bytes = cls._parse_hex_content(val_str)
                current_content = SnortContentMatch(content=raw_bytes, is_negated=is_neg)
                content_matches.append(current_content)
            elif tok == "nocase" and current_content:
                current_content.nocase = True
            elif tok.startswith("offset:") and current_content:
                current_content.offset = int(tok[7:].strip())
            elif tok.startswith("depth:") and current_content:
                current_content.depth = int(tok[6:].strip())
            elif tok.startswith("pcre:"):
                pcre_str = tok[5:].strip(' "/')
                try:
                    pcre_pattern = re.compile(pcre_str.encode("latin-1"), re.IGNORECASE)
                except Exception:
                    pass
            elif tok.startswith("flow:"):
                flow = tok[5:].strip()

        return SnortRule(
            action=action,
            protocol=proto,
            src_net=src_net,
            src_port=src_port,
            direction=direction,
            dst_net=dst_net,
            dst_port=dst_port,
            msg=msg,
            sid=sid,
            rev=rev,
            classtype=classtype,
            severity=severity,
            mitre_attack=mitre,
            cve=cves,
            content_matches=content_matches,
            pcre_regex=pcre_pattern,
            flow=flow,
        )

    @staticmethod
    def _parse_hex_content(raw: str) -> bytes:
        """Parses Snort content with embedded hex blocks (e.g. `|90 90 90|bin/sh|00|`)."""
        parts = []
        in_hex = False
        buffer = []
        for char in raw:
            if char == "|":
                if in_hex:
                    # Convert hex buffer
                    hex_str = "".join(buffer).replace(" ", "")
                    try:
                        parts.append(bytes.fromhex(hex_str))
                    except ValueError:
                        pass
                    buffer = []
                    in_hex = False
                else:
                    if buffer:
                        parts.append("".join(buffer).encode("latin-1", errors="ignore"))
                        buffer = []
                    in_hex = True
            else:
                buffer.append(char)

        if buffer:
            if in_hex:
                hex_str = "".join(buffer).replace(" ", "")
                try:
                    parts.append(bytes.fromhex(hex_str))
                except ValueError:
                    pass
            else:
                parts.append("".join(buffer).encode("latin-1", errors="ignore"))

        return b"".join(parts)


class SnortIDSEngine:
    """Network IDS inspection engine matching live payloads against compiled Snort/Suricata rules."""

    def __init__(self):
        self.rules: List[SnortRule] = []
        self._load_cve_rule_catalog()

    def add_rule_text(self, rule_text: str) -> Optional[SnortRule]:
        rule = SnortCompiler.compile_rule_text(rule_text)
        if rule:
            self.rules.append(rule)
        return rule

    def inspect_flow(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        proto: str,
        payload: Union[bytes, str],
    ) -> List[Dict[str, Any]]:
        """Inspects network payload buffer and returns list of triggered IDS alerts."""
        raw_payload = payload.encode("latin-1", errors="ignore") if isinstance(payload, str) else payload
        alerts = []
        for r in self.rules:
            hit = r.match_packet(src_ip, src_port, dst_ip, dst_port, proto, raw_payload)
            if hit:
                alerts.append(hit)
        return alerts

    def _load_cve_rule_catalog(self):
        """Loads default enterprise CVE exploit signatures."""
        from .ids_signatures import get_enterprise_ids_signatures
        for raw_rule in get_enterprise_ids_signatures():
            self.add_rule_text(raw_rule)


# Global instance
snort_ids = SnortIDSEngine()
