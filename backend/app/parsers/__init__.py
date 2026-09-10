from .base_parser import ParsedRecord, ParserError, BaseParser
from .csv_parser import CSVParser
from .json_parser import JSONParser
from .syslog_parser import SyslogParser
from .cef_parser import CEFParser
from .windows_parser import WindowsEventParser

PARSERS: dict[str, BaseParser] = {
    "csv": CSVParser(),
    "json": JSONParser(),
    "syslog": SyslogParser(),
    "cef": CEFParser(),
    "windows": WindowsEventParser(),
}
