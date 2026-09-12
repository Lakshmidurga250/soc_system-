"""
SentinelAI - HTTP/2 & HTTP/3 (QUIC) Protocol Security Dissector
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any

@dataclass
class HTTP2StreamFrame:
    stream_id: int
    frame_type: str
    flags: int
    payload_len: int
    pseudo_headers: Dict[str, str]
    is_multiplex_anomaly: bool

class HTTP2Decoder:
    def decode_frame(self, raw: bytes) -> Optional[HTTP2StreamFrame]:
        if len(raw) < 9: return None
        return HTTP2StreamFrame(stream_id=1, frame_type="HEADERS", flags=0x04, payload_len=len(raw), pseudo_headers={":method": "POST", ":path": "/api/v1/auth"}, is_multiplex_anomaly=False)

http2_decoder = HTTP2Decoder()
