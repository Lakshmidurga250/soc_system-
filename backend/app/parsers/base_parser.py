from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable

class ParserError(ValueError):
    """Raised for a malformed source document or record."""

@dataclass(slots=True)
class ParsedRecord:
    values: dict[str, Any]
    row_number: int
    warnings: list[str] = field(default_factory=list)

class BaseParser(ABC):
    supported_extensions: tuple[str, ...] = ()
    @abstractmethod
    def parse(self, payload: bytes) -> Iterable[ParsedRecord]: ...
