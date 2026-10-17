"""Stage 2: ddrescue / Scalpel fault-tolerant stream carver & SafeKaitaiStream.
Wraps SafeByteCursor with complete KaitaiStream API and bitmapped byte coverage.
"""

from __future__ import annotations
import struct
from typing import Optional, Tuple
from src.cursor import SafeByteCursor
from src.models import DamageEvent

class SafeKaitaiStream:
    """Fault-tolerant KaitaiStream implementation powered by SafeByteCursor."""

    def __init__(self, data: bytes, filename: str = ""):
        self.cursor = SafeByteCursor(data, filename)

    @property
    def data(self) -> bytes:
        return self.cursor.data

    def size(self) -> int:
        return self.cursor.size

    def pos(self) -> int:
        return self.cursor.pos

    def is_eof(self) -> bool:
        return self.cursor.is_eof()

    def seek(self, target: int) -> bool:
        return self.cursor.seek(target)

    def read_bytes(self, n: int, component: str = "stream") -> Tuple[bytes, bool]:
        return self.cursor.read_bytes(n, component)

    def read_u1(self, component: str = "u1") -> Tuple[int, bool]:
        return self.cursor.read_u8(component)

    def read_u2le(self, component: str = "u2le") -> Tuple[int, bool]:
        return self.cursor.read_u16_le(component)

    def read_u4le(self, component: str = "u4le") -> Tuple[int, bool]:
        return self.cursor.read_u32_le(component)

    def read_s2le(self, component: str = "s2le") -> Tuple[int, bool]:
        return self.cursor.read_i16_le(component)

    def read_s4le(self, component: str = "s4le") -> Tuple[int, bool]:
        return self.cursor.read_i32_le(component)

    def read_f4le(self, component: str = "f4le") -> Tuple[float, bool]:
        return self.cursor.read_float_le(component)

    def read_f8le(self, component: str = "f8le") -> Tuple[float, bool]:
        return self.cursor.read_double_le(component)

    def scan_for_sync(self, sync_bytes: bytes, max_scan: int = 65536) -> int:
        """Scalpel/ddrescue block carver: scans forward to next valid sync boundary."""
        return self.cursor.scan_for_sync(sync_bytes, max_scan=max_scan)

    def get_damage_log(self) -> list[DamageEvent]:
        return self.cursor.get_damage_log()

    def coverage_ratio(self) -> float:
        return self.cursor.coverage_ratio()
