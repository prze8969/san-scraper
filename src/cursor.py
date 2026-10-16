"""Stage 2: SafeByteCursor & DamageTracker.
Fault-tolerant binary cursor that wraps raw bytes and tracks damages, byte claiming,
and never raises unhandled bounds or unpack exceptions.
"""

from __future__ import annotations
import struct
from typing import Any, Optional
from src.models import DamageEvent, DamageItem, DamageKind

class SafeByteCursor:
    """A robust, non-crashing byte cursor with coverage tracking and error logging."""

    def __init__(self, data: bytes) -> None:
        self.data: bytes = bytes(data) if not isinstance(data, bytes) else data
        self.size: int = len(self.data)
        self.pos: int = 0
        self.claimed_bitmap: bytearray = bytearray(self.size)
        self.damages: list[DamageEvent] = []
        self.legacy_damages: list[DamageItem] = []

    def can_read(self, n: int) -> bool:
        """Returns True if at least n bytes remain from the current position."""
        return self.pos + n <= self.size

    def remaining(self) -> int:
        return max(0, self.size - self.pos)

    def is_eof(self) -> bool:
        return self.pos >= self.size

    def _mark_claimed(self, start: int, end: int) -> None:
        s = max(0, min(self.size, start))
        e = max(0, min(self.size, end))
        for i in range(s, e):
            self.claimed_bitmap[i] = 1

    def _make_hex_preview(self, offset: int, length: int = 32) -> str:
        s = max(0, min(self.size, offset))
        e = min(self.size, s + length)
        return self.data[s:e].hex()

    def log_damage(
        self,
        severity: str,
        component: str,
        message: str,
        offset_start: int,
        offset_end: int,
        legacy_kind: DamageKind | str = DamageKind.TRUNCATED,
    ) -> DamageEvent:
        event = DamageEvent(
            offset_start=offset_start,
            offset_end=offset_end,
            severity=severity,
            component=component,
            message=message,
            raw_hex_preview=self._make_hex_preview(offset_start, min(32, max(0, offset_end - offset_start))),
        )
        self.damages.append(event)
        self.legacy_damages.append(
            DamageItem(
                kind=legacy_kind,
                offset=offset_start,
                detail=f"[{component}] {message}",
                lossy=True,
            )
        )
        return event

    def seek(self, offset: int, component: str = "seek") -> bool:
        """Seeks to offset. If out of bounds, logs DamageEvent and clamps or returns False."""
        if offset < 0 or offset > self.size:
            self.log_damage(
                severity="OUT_OF_BOUNDS",
                component=component,
                message=f"Attempted to seek to {offset} outside file bounds [0, {self.size}]",
                offset_start=max(0, min(self.size, offset)),
                offset_end=max(0, min(self.size, offset)),
                legacy_kind=DamageKind.OOB_POINTER,
            )
            self.pos = max(0, min(self.size, offset))
            return False
        self.pos = offset
        return True

    def skip(self, n: int, component: str = "skip") -> bool:
        if n < 0:
            return self.seek(self.pos + n, component)
        if self.pos + n > self.size:
            start_off = self.pos
            self.pos = self.size
            self.log_damage(
                severity="TRUNCATION",
                component=component,
                message=f"Attempted to skip {n} bytes with only {self.remaining()} remaining",
                offset_start=start_off,
                offset_end=self.size,
                legacy_kind=DamageKind.TRUNCATED,
            )
            return False
        self.pos += n
        return True

    def read_bytes(self, n: int, component: str = "bytes", allow_partial: bool = True) -> tuple[bytes, bool]:
        """Reads n bytes. If truncated, logs TRUNCATION DamageEvent and returns partial."""
        if n < 0:
            return b"", False
        if self.pos + n > self.size:
            avail = max(0, self.size - self.pos)
            start_off = self.pos
            partial = self.data[self.pos : self.size]
            self._mark_claimed(self.pos, self.size)
            self.pos = self.size
            self.log_damage(
                severity="TRUNCATION",
                component=component,
                message=f"Truncation while reading {n} bytes (only {avail} available)",
                offset_start=start_off,
                offset_end=self.size,
                legacy_kind=DamageKind.TRUNCATED,
            )
            return (partial if allow_partial else b""), False
        start_off = self.pos
        end_off = self.pos + n
        data_slice = self.data[start_off:end_off]
        self._mark_claimed(start_off, end_off)
        self.pos = end_off
        return data_slice, True

    def peek_bytes(self, n: int, offset: Optional[int] = None) -> bytes:
        start = self.pos if offset is None else offset
        if start < 0 or start >= self.size:
            return b""
        end = min(self.size, start + max(0, n))
        return self.data[start:end]

    def read_primitive(self, fmt: str, component: str = "primitive", default: Any = None) -> tuple[Any, bool]:
        """Reads a struct format primitive safely."""
        size = struct.calcsize(fmt)
        raw, ok = self.read_bytes(size, component=component, allow_partial=False)
        if not ok or len(raw) < size:
            return default, False
        try:
            val = struct.unpack(fmt, raw)[0]
            return val, True
        except Exception as e:
            self.log_damage(
                severity="ERROR",
                component=component,
                message=f"Failed to unpack format '{fmt}': {e}",
                offset_start=self.pos - size,
                offset_end=self.pos,
                legacy_kind=DamageKind.INVALID_VALUE,
            )
            return default, False

    def read_u8(self, component: str = "u8", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive("<B", component, default)

    def read_u16_le(self, component: str = "u16_le", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive("<H", component, default)

    def read_u16_be(self, component: str = "u16_be", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive(">H", component, default)

    def read_u32_le(self, component: str = "u32_le", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive("<I", component, default)

    def read_u32_be(self, component: str = "u32_be", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive(">I", component, default)

    def read_i16_le(self, component: str = "i16_le", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive("<h", component, default)

    def read_i32_le(self, component: str = "i32_le", default: int = 0) -> tuple[int, bool]:
        return self.read_primitive("<i", component, default)

    def read_f32_le(self, component: str = "f32_le", default: float = 0.0) -> tuple[float, bool]:
        return self.read_primitive("<f", component, default)

    def read_f64_le(self, component: str = "f64_le", default: float = 0.0) -> tuple[float, bool]:
        return self.read_primitive("<d", component, default)

    def read_cstring(self, max_len: int, component: str = "cstring", encoding: str = "latin-1") -> tuple[str, bool]:
        """Reads a null-terminated string up to max_len bytes."""
        start = self.pos
        limit = min(self.size, self.pos + max_len)
        null_pos = self.data.find(b"\x00", start, limit)
        if null_pos != -1:
            raw = self.data[start:null_pos]
            self._mark_claimed(start, null_pos + 1)
            self.pos = null_pos + 1
            text = raw.decode(encoding, errors="replace")
            return text, True
        else:
            # Unterminated or reached limit/EOF
            raw = self.data[start:limit]
            self._mark_claimed(start, limit)
            self.pos = limit
            text = raw.decode(encoding, errors="replace")
            self.log_damage(
                severity="TRUNCATION" if limit == self.size else "WARNING",
                component=component,
                message=f"String not null-terminated within {max_len} bytes",
                offset_start=start,
                offset_end=limit,
                legacy_kind=DamageKind.TRUNCATED if limit == self.size else DamageKind.BAD_LENGTH,
            )
            return text, False

    def scan_for_sync(self, sync_bytes: bytes, max_scan: int = 65536, component: str = "resync") -> Optional[int]:
        """Scans forward from current pos for sync_bytes, logging skipped corrupted bytes."""
        start = self.pos
        limit = min(self.size, self.pos + max_scan)
        idx = self.data.find(sync_bytes, start, limit)
        if idx == -1:
            return None
        if idx > start:
            self.log_damage(
                severity="ERROR",
                component=component,
                message=f"Skipping {idx - start} corrupted bytes to synchronize at offset {idx}",
                offset_start=start,
                offset_end=idx,
                legacy_kind=DamageKind.UNPARSED_BYTES,
            )
        self.pos = idx
        return idx

    def get_unclaimed_ranges(self) -> list[tuple[int, int]]:
        """Returns list of contiguous (start, end) unread/unclaimed byte ranges."""
        ranges: list[tuple[int, int]] = []
        in_unclaimed = False
        start_idx = 0
        for i, val in enumerate(self.claimed_bitmap):
            if val == 0 and not in_unclaimed:
                in_unclaimed = True
                start_idx = i
            elif val == 1 and in_unclaimed:
                in_unclaimed = False
                ranges.append((start_idx, i))
        if in_unclaimed:
            ranges.append((start_idx, self.size))
        return ranges

    def coverage_ratio(self) -> float:
        """Returns ratio of claimed bytes to total file size."""
        if self.size == 0:
            return 1.0
        return sum(self.claimed_bitmap) / float(self.size)
