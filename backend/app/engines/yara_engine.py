"""SentinelAI YARA Malware Signature Compilation & Binary Scanning Engine.

Provides an offline, pure-Python YARA rule compiler and pattern matcher
capable of matching binary strings, hex patterns, regular expressions,
and complex boolean evaluation conditions across file samples and process dumps.
Zero external cloud or binary dependencies — 100% locally executable.
"""

from __future__ import annotations

import binascii
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class StringType(str, Enum):
    TEXT = "text"
    HEX = "hex"
    REGEX = "regex"


@dataclass
class YaraStringDefinition:
    identifier: str  # e.g., "$s1", "$a", "$hex_pattern"
    string_type: StringType
    value: Union[str, bytes, re.Pattern]
    nocase: bool = False
    wide: bool = False
    ascii: bool = True
    fullword: bool = False


@dataclass
class YaraRuleMetadata:
    name: str
    category: str
    threat_actor: Optional[str]
    malware_family: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    mitre_attack: List[str]
    description: str
    author: str
    date: str
    references: List[str] = field(default_factory=list)


@dataclass
class YaraCompiledRule:
    meta: YaraRuleMetadata
    strings: List[YaraStringDefinition]
    condition_expression: str

    def scan_data(self, data: Union[bytes, str]) -> Optional[Dict[str, Any]]:
        """Scans byte buffer or string against this compiled YARA rule."""
        raw_bytes = data.encode("utf-8", errors="ignore") if isinstance(data, str) else data
        matched_strings: List[Dict[str, Any]] = []

        string_match_map: Dict[str, bool] = {}

        for str_def in self.strings:
            is_matched, offset, matched_val = self._match_single_string(str_def, raw_bytes)
            string_match_map[str_def.identifier] = is_matched
            if is_matched:
                matched_strings.append({
                    "identifier": str_def.identifier,
                    "offset": offset,
                    "matched_sample": matched_val[:60],
                })

        # Evaluate condition
        condition_satisfied = self._evaluate_condition(self.condition_expression, string_match_map)
        if not condition_satisfied:
            return None

        return {
            "rule_name": self.meta.name,
            "malware_family": self.meta.malware_family,
            "severity": self.meta.severity,
            "category": self.meta.category,
            "threat_actor": self.meta.threat_actor,
            "mitre_attack": self.meta.mitre_attack,
            "description": self.meta.description,
            "matched_strings_count": len(matched_strings),
            "matched_strings": matched_strings,
        }

    def _match_single_string(self, str_def: YaraStringDefinition, raw_bytes: bytes) -> Tuple[bool, int, str]:
        """Tests individual string/hex/regex matching against byte buffer."""
        if str_def.string_type == StringType.HEX:
            # Hex pattern matching
            hex_needle = str_def.value if isinstance(str_def.value, bytes) else bytes.fromhex(str(str_def.value).replace(" ", ""))
            pos = raw_bytes.find(hex_needle)
            if pos != -1:
                return True, pos, binascii.hexlify(hex_needle).decode("ascii")
            return False, -1, ""

        elif str_def.string_type == StringType.REGEX:
            pattern = str_def.value if isinstance(str_def.value, re.Pattern) else re.compile(str(str_def.value).encode("utf-8"), re.IGNORECASE if str_def.nocase else 0)
            m = pattern.search(raw_bytes)
            if m:
                return True, m.start(), m.group(0).decode("latin-1", errors="ignore")
            return False, -1, ""

        else:
            # Text matching with ascii/wide support
            text_str = str(str_def.value)
            candidates: List[bytes] = []
            if str_def.ascii:
                candidates.append(text_str.encode("latin-1", errors="ignore"))
            if str_def.wide:
                candidates.append(text_str.encode("utf-16le", errors="ignore"))

            for target in candidates:
                if str_def.nocase:
                    pos = raw_bytes.lower().find(target.lower())
                else:
                    pos = raw_bytes.find(target)

                if pos != -1:
                    # Check fullword boundary if requested
                    if str_def.fullword:
                        before = chr(raw_bytes[pos - 1]) if pos > 0 else " "
                        after = chr(raw_bytes[pos + len(target)]) if (pos + len(target)) < len(raw_bytes) else " "
                        if before.isalnum() or after.isalnum() or before == "_" or after == "_":
                            continue
                    return True, pos, target.decode("latin-1", errors="ignore")

            return False, -1, ""

    def _evaluate_condition(self, expr: str, match_map: Dict[str, bool]) -> bool:
        """Evaluates YARA condition expressions (e.g. '$s1 and ($s2 or $s3)', 'all of them', '2 of ($a*)')."""
        clean_expr = expr.strip()

        if clean_expr in ("all of them", "all of *"):
            return bool(match_map) and all(match_map.values())
        if clean_expr in ("any of them", "1 of them", "1 of *"):
            return any(match_map.values())

        # Wildcard or list count: '2 of them', '3 of ($s*)', or '2 of ($s1, $s2, $s3)'
        m_count = re.match(r"^(\d+)\s+of\s+\(?([^\)]+)\)?$", clean_expr)
        if m_count:
            req_count = int(m_count.group(1))
            raw_targets = m_count.group(2).strip()
            if raw_targets in ("them", "*"):
                return sum(1 for v in match_map.values() if v) >= req_count
            
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]
            matched_count = 0
            for t in targets:
                if "*" in t:
                    pat = t.replace("*", ".*").replace("$", r"\$")
                    matched_count += sum(1 for k, v in match_map.items() if v and re.match(f"^{pat}$", k))
                else:
                    if match_map.get(t, False):
                        matched_count += 1
            return matched_count >= req_count


        # Safe Boolean token evaluation
        tokens = clean_expr.replace("(", " ( ").replace(")", " ) ").split()
        pos = [0]

        def parse_or() -> bool:
            left = parse_and()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "or":
                pos[0] += 1
                right = parse_and()
                left = left or right
            return left

        def parse_and() -> bool:
            left = parse_not()
            while pos[0] < len(tokens) and tokens[pos[0]].lower() == "and":
                pos[0] += 1
                right = parse_not()
                left = left and right
            return left

        def parse_not() -> bool:
            if pos[0] < len(tokens) and tokens[pos[0]].lower() == "not":
                pos[0] += 1
                return not parse_not()
            return parse_primary()

        def parse_primary() -> bool:
            if pos[0] >= len(tokens):
                return False
            t = tokens[pos[0]]
            pos[0] += 1
            if t == "(":
                res = parse_or()
                if pos[0] < len(tokens) and tokens[pos[0]] == ")":
                    pos[0] += 1
                return res
            return match_map.get(t, False)

        try:
            return parse_or()
        except Exception:
            return match_map.get(clean_expr, False)


class YaraEngine:
    """Enterprise YARA Scanning & Threat Signature Engine."""

    def __init__(self):
        self.rules: List[YaraCompiledRule] = []
        self._load_signature_database()

    def register_rule(self, rule: YaraCompiledRule) -> None:
        self.rules.append(rule)

    def scan_payload(self, data: Union[bytes, str]) -> List[Dict[str, Any]]:
        """Scans a file buffer or telemetry string against all loaded YARA rules."""
        hits = []
        for r in self.rules:
            hit = r.scan_data(data)
            if hit:
                hits.append(hit)
        return hits

    def _load_signature_database(self):
        """Loads default enterprise signature catalog for known malware families."""
        # Built-in signature definitions loaded directly
        from .yara_rules_catalog import get_enterprise_yara_catalog
        for rule in get_enterprise_yara_catalog():
            self.register_rule(rule)


# Singleton
yara_scanner = YaraEngine()
