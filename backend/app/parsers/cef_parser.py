import re
from .base_parser import BaseParser, ParsedRecord, ParserError

# CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
CEF_HEADER_RE = re.compile(
    r"^CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$"
)

class CEFParser(BaseParser):
    supported_extensions = (".cef",)

    def parse(self, payload: bytes):
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = payload.decode("latin-1")
            except UnicodeDecodeError as exc:
                raise ParserError("CEF payload is not valid text") from exc

        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            raise ParserError("CEF log file is empty")

        for index, line in enumerate(lines, start=1):
            m = CEF_HEADER_RE.match(line)
            if not m:
                if "CEF:" in line:
                    idx = line.find("CEF:")
                    line = line[idx:]
                    m = CEF_HEADER_RE.match(line)

            if not m:
                raise ParserError(f"Line {index} does not conform to CEF format")

            version, vendor, product, dev_ver, sig_id, name, sev_str, ext = m.groups()
            extensions = self._parse_extensions(ext)

            # Map CEF standard severity (0-10) to SentinelAI severity
            try:
                sev_num = int(sev_str)
                if sev_num >= 8:
                    mapped_sev = "CRITICAL"
                elif sev_num >= 6:
                    mapped_sev = "HIGH"
                elif sev_num >= 4:
                    mapped_sev = "MEDIUM"
                else:
                    mapped_sev = "LOW"
            except ValueError:
                mapped_sev = "MEDIUM" if not sev_str else sev_str.upper()

            action_val = str(extensions.get("act") or extensions.get("action") or "").lower()
            name_val = str(name).lower()
            is_failure = any(w in action_val or w in name_val for w in ("fail", "block", "deny", "denied", "drop", "alert", "attack", "detected", "scan"))
            status = "FAILURE" if is_failure else "SUCCESS"

            record = {
                "source": "cef",
                "event_type": name or sig_id or "cef_event",
                "severity": mapped_sev,
                "raw_message": line,
                "source_ip": extensions.get("src") or extensions.get("sourceAddress"),
                "destination_ip": extensions.get("dst") or extensions.get("destinationAddress"),
                "username": extensions.get("suser") or extensions.get("duser") or extensions.get("user") or extensions.get("username"),
                "hostname": extensions.get("shost") or extensions.get("dhost") or extensions.get("hostname") or product,
                "resource": extensions.get("request") or extensions.get("cs1") or extensions.get("resource"),
                "action": extensions.get("act") or extensions.get("action"),
                "category": extensions.get("cat") or "security",
                "status": status,
            }
            yield ParsedRecord(record, index)

    def _parse_extensions(self, ext_str: str) -> dict:
        result = {}
        tokens = re.findall(r'(\w+)=((?:\\=|[^=])+?)(?=(?:\s+\w+=)|$)', ext_str)
        for k, v in tokens:
            result[k.strip()] = v.strip().replace(r"\=", "=")
        return result
