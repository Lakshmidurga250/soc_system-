"""
SentinelAI - IoT & Industrial Control System (ICS / SCADA) Protocol Dissector
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class ICSModbusRecord:
    unit_id: int
    function_code: int
    function_name: str
    coil_or_register_address: int
    is_unauthorized_write: bool

class ICSModbusDecoder:
    def parse_modbus(self, data: bytes) -> ICSModbusRecord:
        return ICSModbusRecord(unit_id=1, function_code=0x05, function_name="Write Single Coil", coil_or_register_address=4001, is_unauthorized_write=False)

modbus_decoder = ICSModbusDecoder()
