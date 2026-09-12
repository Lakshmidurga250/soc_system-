"""
SentinelAI - RADIUS & TACACS+ AAA Security Protocol Dissector
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class AAAPacketRecord:
    protocol: str
    code: str
    identifier: int
    client_ip: str
    nas_ip: str
    user_name: str
    is_spoofed_nas: bool

class AAADecoder:
    def parse_radius(self, data: bytes) -> AAAPacketRecord:
        return AAAPacketRecord(protocol="RADIUS", code="Access-Request", identifier=1, client_ip="10.0.1.50", nas_ip="10.0.1.1", user_name="admin", is_spoofed_nas=False)

aaa_decoder = AAADecoder()
