"""SentinelAI Sigma Detection Rule Compiler & Execution Engine.

Compiles Sigma YAML/JSON detection rules into executable abstract syntax trees (AST)
and evaluates them at high throughput against normalized telemetry events.
Zero external cloud dependency — 100% offline rule compilation and matching.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union


class MatchModifier(str, Enum):
    EXACT = "exact"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "re"
    CIDR = "cidr"
    BASE64 = "base64"
    BASE64_OFFSET = "base64offset"
    WINDASH = "windash"
    ALL = "all"


@dataclass
class SigmaRuleMetadata:
    id: str
    title: str
    description: str
    level: str  # low, medium, high, critical
    status: str  # experimental, test, stable
    author: str
    date: str
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    logsource: Dict[str, str] = field(default_factory=dict)


@dataclass
class CompiledFieldMatch:
    field_name: str
    modifiers: List[MatchModifier]
    expected_values: List[Any]
    compiled_regexes: List[re.Pattern] = field(default_factory=list)
    compiled_networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = field(default_factory=list)

    def evaluate(self, event_data: Dict[str, Any]) -> bool:
        """Evaluates whether the event data satisfies this field matcher."""
        actual_val = self._extract_field_val(event_data, self.field_name)
        if actual_val is None:
            return False

        actual_str = str(actual_val)
        require_all = MatchModifier.ALL in self.modifiers

        matches = []
        if MatchModifier.REGEX in self.modifiers:
            for pattern in self.compiled_regexes:
                matches.append(bool(pattern.search(actual_str)))
        elif MatchModifier.CIDR in self.modifiers:
            try:
                ip_obj = ipaddress.ip_address(actual_str.strip())
                for net in self.compiled_networks:
                    matches.append(ip_obj in net)
            except ValueError:
                matches.append(False)
        elif MatchModifier.CONTAINS in self.modifiers:
            for exp in self.expected_values:
                matches.append(str(exp).lower() in actual_str.lower())
        elif MatchModifier.STARTSWITH in self.modifiers:
            for exp in self.expected_values:
                matches.append(actual_str.lower().startswith(str(exp).lower()))
        elif MatchModifier.ENDSWITH in self.modifiers:
            for exp in self.expected_values:
                matches.append(actual_str.lower().endswith(str(exp).lower()))
        elif MatchModifier.WINDASH in self.modifiers:
            # Handles Windows switch variations: /switch, -switch, --switch
            normalized_actual = re.sub(r"^[/\-]+", "-", actual_str.lower())
            for exp in self.expected_values:
                normalized_exp = re.sub(r"^[/\-]+", "-", str(exp).lower())
                matches.append(normalized_exp in normalized_actual)
        else:
            # Exact match (case-insensitive for string comparison)
            for exp in self.expected_values:
                if isinstance(actual_val, (int, float)) and isinstance(exp, (int, float)):
                    matches.append(actual_val == exp)
                else:
                    matches.append(str(exp).lower() == actual_str.lower())

        if not matches:
            return False
        return all(matches) if require_all else any(matches)

    @staticmethod
    def _extract_field_val(data: Dict[str, Any], field: str) -> Any:
        """Extracts field value supporting dotted notation and common aliases."""
        if field in data:
            return data[field]

        # Field alias mapping
        aliases = {
            "image": ["process_name", "process_path", "image_path", "exe", "Image"],
            "commandline": ["command_line", "cmdline", "CommandLine", "args", "cmd"],
            "parentimage": ["parent_process", "parent_image", "ParentImage", "ppid_name"],
            "parentcommandline": ["parent_command_line", "ParentCommandLine", "parent_cmd"],
            "user": ["user_name", "username", "account", "User", "src_user"],
            "destinationip": ["dest_ip", "destination_ip", "dst_ip", "DestinationIp", "remote_ip"],
            "destinationport": ["dest_port", "destination_port", "dst_port", "DestinationPort"],
            "sourceip": ["source_ip", "src_ip", "SourceIp"],
            "sourceport": ["source_port", "src_port", "SourcePort"],
            "targetfilename": ["file_name", "file_path", "target_file", "TargetFilename"],
            "eventid": ["event_id", "EventID", "id"],
            "targetobject": ["registry_path", "TargetObject", "reg_key"],
            "hashes": ["file_hash", "hash", "Hashes", "sha256", "md5"],
            "queryname": ["dns_query", "query", "QueryName", "domain"],
            "servicename": ["service_name", "ServiceName"],
        }

        low_field = field.lower().replace("_", "")
        if low_field in aliases:
            for alias in aliases[low_field]:
                if alias in data:
                    return data[alias]
                if alias.lower() in data:
                    return data[alias.lower()]

        # Nested lookup
        if "." in field:
            curr = data
            for part in field.split("."):
                if isinstance(curr, dict) and part in curr:
                    curr = curr[part]
                else:
                    return None
            return curr

        # Fallback case-insensitive check
        for k, v in data.items():
            if k.lower().replace("_", "") == low_field:
                return v

        return None


@dataclass
class SigmaSelection:
    name: str
    field_matchers: List[CompiledFieldMatch] = field(default_factory=list)
    raw_list_values: List[str] = field(default_factory=list)

    def evaluate(self, event_data: Dict[str, Any]) -> bool:
        if self.field_matchers:
            return all(matcher.evaluate(event_data) for matcher in self.field_matchers)
        elif self.raw_list_values:
            # Keyword search across entire event content
            event_repr = str(event_data).lower()
            return any(val.lower() in event_repr for val in self.raw_list_values)
        return False


class SigmaConditionEvaluator:
    """Parses and executes Sigma detection condition expressions."""

    def __init__(self, condition_str: str, selections: Dict[str, SigmaSelection]):
        self.condition_str = condition_str.strip()
        self.selections = selections

    def evaluate(self, event_data: Dict[str, Any]) -> bool:
        """Evaluates condition against event using selection map."""
        cond = self.condition_str

        # 1. Handle wildcard aggregators: '1 of them', 'all of them', '1 of selection*', 'all of selection*'
        if cond in ("1 of them", "1 of *"):
            return any(sel.evaluate(event_data) for sel in self.selections.values())
        if cond in ("all of them", "all of *"):
            return bool(self.selections) and all(sel.evaluate(event_data) for sel in self.selections.values())

        m_one_pattern = re.match(r"1 of ([a-zA-Z0-9_\*]+)", cond)
        if m_one_pattern:
            pattern = m_one_pattern.group(1).replace("*", ".*")
            matched_sels = [s for k, s in self.selections.items() if re.match(f"^{pattern}$", k)]
            return any(s.evaluate(event_data) for s in matched_sels)

        m_all_pattern = re.match(r"all of ([a-zA-Z0-9_\*]+)", cond)
        if m_all_pattern:
            pattern = m_all_pattern.group(1).replace("*", ".*")
            matched_sels = [s for k, s in self.selections.items() if re.match(f"^{pattern}$", k)]
            return bool(matched_sels) and all(s.evaluate(event_data) for s in matched_sels)

        # 2. Evaluate all selections into boolean values
        selection_results = {}
        for name, sel in self.selections.items():
            selection_results[name] = sel.evaluate(event_data)

        # 3. Safe Boolean AST token evaluation
        return self._eval_boolean_expr(cond, selection_results)

    def _eval_boolean_expr(self, expr: str, results: Dict[str, bool]) -> bool:
        """Safely evaluates boolean expression with and, or, not, parentheses."""
        tokens = self._tokenize(expr)
        pos = [0]

        def parse_or() -> bool:
            left = parse_and()
            while pos[0] < len(tokens) and tokens[pos[0]] == "or":
                pos[0] += 1
                right = parse_and()
                left = left or right
            return left

        def parse_and() -> bool:
            left = parse_not()
            while pos[0] < len(tokens) and tokens[pos[0]] == "and":
                pos[0] += 1
                right = parse_not()
                left = left and right
            return left

        def parse_not() -> bool:
            if pos[0] < len(tokens) and tokens[pos[0]] == "not":
                pos[0] += 1
                return not parse_not()
            return parse_primary()

        def parse_primary() -> bool:
            if pos[0] >= len(tokens):
                return False
            token = tokens[pos[0]]
            pos[0] += 1
            if token == "(":
                res = parse_or()
                if pos[0] < len(tokens) and tokens[pos[0]] == ")":
                    pos[0] += 1
                return res
            return results.get(token, False)

        try:
            return parse_or()
        except Exception:
            # Fallback simple selection check
            return results.get(expr.strip(), False)

    @staticmethod
    def _tokenize(expr: str) -> List[str]:
        expr = expr.replace("(", " ( ").replace(")", " ) ")
        raw_tokens = expr.split()
        return [t.lower() if t.lower() in ("and", "or", "not") else t for t in raw_tokens]


@dataclass
class CompiledSigmaRule:
    metadata: SigmaRuleMetadata
    selections: Dict[str, SigmaSelection]
    condition_evaluator: SigmaConditionEvaluator

    def match(self, event_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Tests if the event matches the rule. Returns match summary if positive."""
        if not self.condition_evaluator.evaluate(event_data):
            return None

        # Collect matching selection keys
        matched_selections = [
            k for k, sel in self.selections.items() if sel.evaluate(event_data)
        ]

        return {
            "matched": True,
            "rule_id": self.metadata.id,
            "rule_title": self.metadata.title,
            "severity": self.metadata.level.upper(),
            "description": self.metadata.description,
            "mitre_attack": self.metadata.mitre_attack,
            "mitre_tactics": self.metadata.mitre_tactics,
            "matched_selections": matched_selections,
            "logsource": self.metadata.logsource,
        }


class SigmaCompiler:
    """Compiles Sigma rule dictionaries or YAML structures into high-performance evaluators."""

    @classmethod
    def compile_rule(cls, rule_dict: Dict[str, Any]) -> CompiledSigmaRule:
        """Parses and compiles a single Sigma rule definition."""
        # 1. Metadata
        tags = rule_dict.get("tags", [])
        mitre_attack = [t for t in tags if re.match(r"^attack\.t\d+(\.\d+)?$", t, re.I)]
        mitre_tactics = [t for t in tags if re.match(r"^attack\.(initial_access|execution|persistence|privilege_escalation|defense_evasion|credential_access|discovery|lateral_movement|collection|command_and_control|exfiltration|impact)$", t, re.I)]

        meta = SigmaRuleMetadata(
            id=str(rule_dict.get("id", f"SIGMA-{hash(rule_dict.get('title', '')) & 0xFFFFFF:06X}")),
            title=rule_dict.get("title", "Unnamed Sigma Rule"),
            description=rule_dict.get("description", ""),
            level=rule_dict.get("level", "medium").lower(),
            status=rule_dict.get("status", "stable"),
            author=rule_dict.get("author", "SentinelAI Research"),
            date=str(rule_dict.get("date", "2026-01-01")),
            references=rule_dict.get("references", []),
            tags=tags,
            mitre_attack=mitre_attack,
            mitre_tactics=mitre_tactics,
            falsepositives=rule_dict.get("falsepositives", []),
            logsource=rule_dict.get("logsource", {}),
        )

        # 2. Selections & Filters
        detection_block = rule_dict.get("detection", {})
        condition_str = detection_block.get("condition", "selection")

        selections: Dict[str, SigmaSelection] = {}
        for key, sel_def in detection_block.items():
            if key == "condition":
                continue
            selections[key] = cls._compile_selection(key, sel_def)

        # 3. Condition Evaluator
        evaluator = SigmaConditionEvaluator(condition_str, selections)

        return CompiledSigmaRule(
            metadata=meta,
            selections=selections,
            condition_evaluator=evaluator,
        )

    @classmethod
    def _compile_selection(cls, name: str, sel_def: Any) -> SigmaSelection:
        """Compiles a selection block (mapping or list) into a SigmaSelection object."""
        field_matchers: List[CompiledFieldMatch] = []
        raw_list: List[str] = []

        if isinstance(sel_def, list):
            # Keyword or raw string list
            raw_list = [str(x) for x in sel_def]
        elif isinstance(sel_def, dict):
            for field_spec, values in sel_def.items():
                matcher = cls._compile_field_matcher(field_spec, values)
                field_matchers.append(matcher)

        return SigmaSelection(name=name, field_matchers=field_matchers, raw_list_values=raw_list)

    @classmethod
    def _compile_field_matcher(cls, field_spec: str, values: Any) -> CompiledFieldMatch:
        """Parses field modifiers (e.g. `CommandLine|contains|all`) and compiles regexes/CIDRs."""
        parts = field_spec.split("|")
        field_name = parts[0]
        modifier_tokens = parts[1:]

        modifiers: List[MatchModifier] = []
        for mod in modifier_tokens:
            try:
                modifiers.append(MatchModifier(mod.lower()))
            except ValueError:
                pass

        if not modifiers:
            modifiers = [MatchModifier.EXACT]

        expected_vals = values if isinstance(values, list) else [values]

        compiled_regexes = []
        compiled_networks = []

        if MatchModifier.REGEX in modifiers:
            for v in expected_vals:
                try:
                    compiled_regexes.append(re.compile(str(v), re.IGNORECASE))
                except re.error:
                    pass
        elif MatchModifier.CIDR in modifiers:
            for v in expected_vals:
                try:
                    compiled_networks.append(ipaddress.ip_network(str(v), strict=False))
                except ValueError:
                    pass

        return CompiledFieldMatch(
            field_name=field_name,
            modifiers=modifiers,
            expected_values=expected_vals,
            compiled_regexes=compiled_regexes,
            compiled_networks=compiled_networks,
        )


class SigmaEngine:
    """Manages rule compilation, rule indexing, and bulk event stream matching."""

    def __init__(self):
        self.rules: List[CompiledSigmaRule] = []
        self._load_builtin_rules()

    def add_rule(self, rule_dict: Dict[str, Any]) -> CompiledSigmaRule:
        compiled = SigmaCompiler.compile_rule(rule_dict)
        self.rules.append(compiled)
        return compiled

    def evaluate_event(self, event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluates an event across all loaded Sigma rules and returns match alerts."""
        alerts = []
        for rule in self.rules:
            res = rule.match(event_data)
            if res:
                alerts.append(res)
        return alerts

    def _load_builtin_rules(self):
        """Loads default enterprise Sigma rule catalog."""
        builtin_specs = [
            {
                "id": "SIGMA-001",
                "title": "LSASS Memory Dump via ProcDump",
                "description": "Detects execution of Sysinternals ProcDump targeting the Local Security Authority Subsystem Service (LSASS).",
                "level": "critical",
                "tags": ["attack.t1003.001", "attack.credential_access"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "CommandLine|contains": ["lsass.exe", "lsass"],
                        "Image|contains": ["procdump", "procdump64"],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-002",
                "title": "PowerShell Download Cradle via WebClient or IWR",
                "description": "Detects PowerShell command lines downloading scripts or binaries from remote URIs into memory.",
                "level": "high",
                "tags": ["attack.t1059.001", "attack.execution", "attack.t1105"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_pwsh": {
                        "Image|endswith": ["powershell.exe", "pwsh.exe"],
                    },
                    "selection_cradle": {
                        "CommandLine|contains": [
                            "Net.WebClient",
                            "DownloadString",
                            "DownloadFile",
                            "Invoke-WebRequest",
                            "iwr ",
                            "irm ",
                            "Invoke-RestMethod",
                        ],
                    },
                    "condition": "selection_pwsh and selection_cradle",
                },
            },
            {
                "id": "SIGMA-003",
                "title": "Volume Shadow Copies Deletion via Vssadmin or WMIC",
                "description": "Detects attempts to delete volume shadow copies typical of ransomware pre-encryption behaviors.",
                "level": "critical",
                "tags": ["attack.t1490", "attack.impact"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection_vssadmin": {
                        "Image|endswith": ["vssadmin.exe"],
                        "CommandLine|contains": ["delete", "shadows"],
                    },
                    "selection_wmic": {
                        "Image|endswith": ["wmic.exe"],
                        "CommandLine|contains": ["shadowcopy", "delete"],
                    },
                    "condition": "selection_vssadmin or selection_wmic",
                },
            },
            {
                "id": "SIGMA-004",
                "title": "Persistence via Scheduled Task Creation",
                "description": "Detects use of schtasks.exe to create recurring scheduled tasks for persistence.",
                "level": "medium",
                "tags": ["attack.t1053.005", "attack.persistence"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image|endswith": ["schtasks.exe"],
                        "CommandLine|contains": ["/create", "-create"],
                    },
                    "filter_system": {
                        "CommandLine|contains": ["GoogleUpdate", "MicrosoftEdgeUpdate"],
                    },
                    "condition": "selection and not filter_system",
                },
            },
            {
                "id": "SIGMA-005",
                "title": "Certutil Remote File Download",
                "description": "Detects use of certutil.exe with -urlcache or -split to download arbitrary files.",
                "level": "high",
                "tags": ["attack.t1105", "attack.command_and_control"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image|endswith": ["certutil.exe"],
                        "CommandLine|contains": ["-urlcache", "/urlcache", "-split", "/split"],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-006",
                "title": "Cobalt Strike Default Named Pipe Communication",
                "description": "Detects creation or connection to known Cobalt Strike default named pipe patterns.",
                "level": "critical",
                "tags": ["attack.t1055", "attack.defense_evasion"],
                "logsource": {"category": "pipe_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "TargetObject|contains": [
                            "\\msagent_",
                            "\\status_",
                            "\\MSSE-",
                            "\\postex_",
                            "\\spoolss_",
                        ],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-007",
                "title": "Accessibility Features Backdoor (Sticky Keys Debugger)",
                "description": "Detects modification of Image File Execution Options for sethc.exe or utilman.exe.",
                "level": "critical",
                "tags": ["attack.t1546.008", "attack.persistence", "attack.privilege_escalation"],
                "logsource": {"category": "registry_set", "product": "windows"},
                "detection": {
                    "selection": {
                        "TargetObject|contains": [
                            "Image File Execution Options\\sethc.exe",
                            "Image File Execution Options\\utilman.exe",
                            "Image File Execution Options\\osk.exe",
                            "Image File Execution Options\\Magnify.exe",
                        ],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-008",
                "title": "Suspicious DNS Tunneling High Length Query",
                "description": "Detects DNS queries exceeding 80 characters indicative of C2 data exfiltration or DNS tunneling.",
                "level": "high",
                "tags": ["attack.t1071.004", "attack.exfiltration"],
                "logsource": {"category": "dns", "product": "zeek"},
                "detection": {
                    "selection": {
                        "QueryName|re": [r"^[a-zA-Z0-9+\/=]{60,}\.", r"^[0-9a-f]{50,}\."],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-009",
                "title": "Direct Execution from Temp or Public Directory",
                "description": "Detects binaries or scripts executed directly from world-writable directories.",
                "level": "medium",
                "tags": ["attack.t1059", "attack.defense_evasion"],
                "logsource": {"category": "process_creation", "product": "windows"},
                "detection": {
                    "selection": {
                        "Image|contains": [
                            "\\AppData\\Local\\Temp\\",
                            "\\Users\\Public\\",
                            "C:\\Windows\\Temp\\",
                            "/tmp/",
                            "/var/tmp/",
                            "/dev/shm/",
                        ],
                    },
                    "condition": "selection",
                },
            },
            {
                "id": "SIGMA-010",
                "title": "Linux Sudoers File Unauthorized Modification",
                "description": "Detects direct modification or writing to /etc/sudoers or /etc/sudoers.d/.",
                "level": "critical",
                "tags": ["attack.t1548.003", "attack.privilege_escalation"],
                "logsource": {"category": "file_event", "product": "linux"},
                "detection": {
                    "selection": {
                        "TargetFilename|contains": ["/etc/sudoers", "/etc/sudoers.d/"],
                    },
                    "condition": "selection",
                },
            },
        ]

        for spec in builtin_specs:
            self.add_rule(spec)


# Global singleton instance
sigma_engine = SigmaEngine()
