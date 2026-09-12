"""
SentinelAI - Enterprise SIEM Correlation Rule Engine & Dynamic Query Transpiler
Translates Sigma rules into SPL, KQL, EQL, and OpenSearch DSL with real-time evaluation.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
import re
import json

class QueryLanguage(Enum):
    SPL = "SPL"
    KQL = "KQL"
    EQL = "EQL"
    OPENSEARCH_DSL = "OPENSEARCH_DSL"
    SQL = "SQL"

@dataclass
class CorrelationRuleDefinition:
    rule_id: str
    title: str
    description: str
    severity: str
    log_source: str
    detection_logic: Dict[str, Any]
    timeframe_seconds: int = 300
    threshold_count: int = 1
    mitre_tags: List[str] = field(default_factory=list)

class SiemRuleTranspiler:
    def __init__(self):
        self.rules: Dict[str, CorrelationRuleDefinition] = {}

    def register_rule(self, rule: CorrelationRuleDefinition) -> None:
        self.rules[rule.rule_id] = rule

    def transpile_to_spl(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id)
        if not rule:
            return ""
        conditions = []
        for k, v in rule.detection_logic.items():
            if isinstance(v, list):
                val_str = " OR ".join([f'{k}="{item}"' for item in v])
                conditions.append(f"({val_str})")
            else:
                conditions.append(f'{k}="{v}"')
        filter_str = " AND ".join(conditions)
        return f'index={rule.log_source} {filter_str} | stats count by host, user | where count >= {rule.threshold_count}'

    def transpile_to_kql(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id)
        if not rule:
            return ""
        conditions = []
        for k, v in rule.detection_logic.items():
            if isinstance(v, list):
                val_str = ", ".join([f'"{item}"' for item in v])
                conditions.append(f'{k} in ({val_str})')
            else:
                conditions.append(f'{k} == "{v}"')
        filter_str = " and ".join(conditions)
        return f'{rule.log_source} | where {filter_str} | summarize count() by HostName, UserPrincipalName | where count_ >= {rule.threshold_count}'

    def transpile_to_eql(self, rule_id: str) -> str:
        rule = self.rules.get(rule_id)
        if not rule:
            return ""
        conditions = []
        for k, v in rule.detection_logic.items():
            if isinstance(v, list):
                val_str = ", ".join([f'"{item}"' for item in v])
                conditions.append(f'{k} in ({val_str})')
            else:
                conditions.append(f'{k} == "{v}"')
        filter_str = " and ".join(conditions)
        return f'process where {filter_str}'

siem_transpiler = SiemRuleTranspiler()
