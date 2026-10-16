"""BaseDecoder abstract class and recovery helpers."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult, OutputStatus, SalvagedRecord, DamageEvent

class BaseDecoder(ABC):
    """Abstract base class for all legacy format decoders."""

    @abstractmethod
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        """Decodes raw binary into structured FileRecoveryResult without crashing."""
        pass
