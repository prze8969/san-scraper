"""Bounded binary reading primitives with strict defensive limits."""

from __future__ import annotations
import struct
from typing import Any

class BoundsError(Exception):
    """Raised when an offset or length read exceeds the available buffer bounds."""
    pass

class TruncationError(BoundsError):
    """Raised when an expected field could not be read due to file truncation."""
    pass

class BoundedBinaryReader:
    """A safe, boundary-checked binary reader designed for untrusted files."""

    __slots__ = ("_data", "_size", "_pos", "_max_alloc")

    def __init__(self, data: bytes, max_alloc: int = 32 * 1024 * 1024) -> None:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Data must be bytes-like")
        self._data = bytes(data)
        self._size = len(self._data)
        self._pos = 0
        self._max_alloc = max_alloc

    @property
    def size(self) -> int:
        return self._size

    @property
    def position(self) -> int:
        return self._pos

    @property
    def remaining(self) -> int:
        return max(0, self._size - self._pos)

    def is_eof(self) -> bool:
        return self._pos >= self._size

    def seek(self, offset: int) -> None:
        if offset < 0 or offset > self._size:
            raise BoundsError(f"Seek position {offset} outside buffer [0, {self._size}]")
        self._pos = offset

    def skip(self, length: int) -> None:
        if length < 0:
            raise ValueError("Skip length must be non-negative")
        if self._pos + length > self._size:
            raise TruncationError(
                f"Attempted to skip {length} bytes with only {self.remaining} remaining"
            )
        self._pos += length

    def read_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("Read length cannot be negative")
        if length > self._max_alloc:
            raise BoundsError(f"Requested read length {length} exceeds max allocation limit {self._max_alloc}")
        if self._pos + length > self._size:
            raise TruncationError(
                f"Attempted to read {length} bytes at offset {self._pos}, but file size is {self._size}"
            )
        start = self._pos
        self._pos += length
        return self._data[start:self._pos]

    def peek_bytes(self, length: int, offset: int | None = None) -> bytes:
        """Peek bytes without advancing position."""
        pos = self._pos if offset is None else offset
        if pos < 0 or pos > self._size:
            return b""
        end = min(self._size, pos + max(0, length))
        return self._data[pos:end]

    def read_exact(self, length: int, offset: int) -> bytes:
        """Read exact slice at specific offset without changing current position."""
        if offset < 0 or length < 0 or offset + length > self._size:
            raise BoundsError(f"Slice [{offset}:{offset + length}] out of bounds [0:{self._size}]")
        return self._data[offset:offset + length]

    def unpack(self, fmt: str) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        raw = self.read_bytes(size)
        return struct.unpack(fmt, raw)

    def unpack_at(self, fmt: str, offset: int) -> tuple[Any, ...]:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > self._size:
            raise BoundsError(f"Unpack '{fmt}' at offset {offset} exceeds buffer size {self._size}")
        return struct.unpack(fmt, self._data[offset:offset + size])

    # Primitive numeric readers (Little Endian by default)
    def read_u8(self) -> int:
        return self.unpack("<B")[0]

    def read_i8(self) -> int:
        return self.unpack("<b")[0]

    def read_u16_le(self) -> int:
        return self.unpack("<H")[0]

    def read_u16_be(self) -> int:
        return self.unpack(">H")[0]

    def read_i16_le(self) -> int:
        return self.unpack("<h")[0]

    def read_u32_le(self) -> int:
        return self.unpack("<I")[0]

    def read_u32_be(self) -> int:
        return self.unpack(">I")[0]

    def read_i32_le(self) -> int:
        return self.unpack("<i")[0]

    def read_u64_le(self) -> int:
        return self.unpack("<Q")[0]

    def read_f32_le(self) -> float:
        return self.unpack("<f")[0]

    def read_f64_le(self) -> float:
        return self.unpack("<d")[0]

    def read_fixed_string(self, length: int, encoding: str = "utf-8") -> str:
        raw = self.read_bytes(length)
        # Strip trailing null bytes
        raw = raw.split(b"\x00", 1)[0]
        return raw.decode(encoding, errors="replace")

    def read_all_remaining(self) -> bytes:
        if self._pos >= self._size:
            return b""
        start = self._pos
        self._pos = self._size
        return self._data[start:]
