"""Base parser interface for format decoders."""

from __future__ import annotations
from abc import ABC, abstractmethod
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult

class BaseParser(ABC):
    """Abstract base class for defensive binary format parsers."""

    @abstractmethod
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        """Parses the input reader defensively and returns structured recovery results."""
        pass
