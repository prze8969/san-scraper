"""Integrity and chunk parser for Portable Network Graphics (PNG).

Specification (ISO/IEC 15948 / W3C):
  Header (8 bytes):
    b'\\x89PNG\\r\\n\\x1a\\n'
  Chunks:
    Length (4 bytes, uint32 big-endian)
    Chunk Type (4 bytes ASCII, e.g. IHDR, IDAT, IEND)
    Chunk Data (Length bytes)
    CRC-32 (4 bytes, calculated over Chunk Type + Chunk Data)
"""

from __future__ import annotations
import struct
import zlib
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class PngParser(BaseParser):
    """Defensive PNG chunk parser with per-chunk CRC verification and damage reporting."""

    MAGIC = b"\x89PNG\r\n\x1a\n"
    MAX_CHUNKS = 10000

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        if file_size < 8:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than PNG signature ({file_size} < 8)",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PNG",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                damages=damages,
            )

        magic = reader.read_bytes(8)
        if magic != self.MAGIC:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=8,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid PNG signature: {magic.hex()}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PNG",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                damages=damages,
            )

        is_valid_header = True
        chunk_idx = 0
        saw_ihdr = False
        saw_iend = False
        width, height = 0, 0

        while not reader.is_eof() and chunk_idx < self.MAX_CHUNKS:
            chunk_start = reader.position
            if reader.remaining < 8:
                damages.append(
                    DamageBlock(
                        offset=chunk_start,
                        length=reader.remaining,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Truncated chunk header at offset {chunk_start}",
                    )
                )
                break

            chunk_len = reader.read_u32_be()
            chunk_type_bytes = reader.read_bytes(4)
            chunk_type = chunk_type_bytes.decode("latin-1", errors="replace")

            if chunk_type == "IHDR":
                saw_ihdr = True

            # Check if chunk data + CRC fits in remaining buffer
            if reader.remaining < chunk_len + 4:
                damages.append(
                    DamageBlock(
                        offset=chunk_start,
                        length=reader.remaining + 8,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Chunk '{chunk_type}' data truncated: expected {chunk_len + 4}B, got {reader.remaining}B",
                    )
                )
                break

            chunk_data = reader.read_bytes(chunk_len)
            stored_crc = reader.read_u32_be()
            chunk_end = reader.position

            # Verify CRC-32 over Type + Data
            calc_crc = zlib.crc32(chunk_type_bytes + chunk_data) & 0xFFFFFFFF
            errors: list[str] = []
            rec_status = RecordStatus.COMPLETE

            if calc_crc != stored_crc:
                rec_status = RecordStatus.CORRUPTED
                err_msg = f"CRC-32 mismatch on chunk '{chunk_type}': declared 0x{stored_crc:08X}, computed 0x{calc_crc:08X}"
                errors.append(err_msg)
                damages.append(
                    DamageBlock(
                        offset=chunk_end - 4,
                        length=4,
                        damage_type=DamageType.CHECKSUM_MISMATCH,
                        description=err_msg,
                    )
                )

            rec_fields: dict = {
                "chunk_type": chunk_type,
                "length": chunk_len,
                "crc32": f"0x{stored_crc:08X}",
                "crc_status": "verified" if calc_crc == stored_crc else "mismatch",
            }

            if chunk_type == "IHDR" and len(chunk_data) >= 8:
                width, height = struct.unpack(">II", chunk_data[:8])
                rec_fields["width"] = width
                rec_fields["height"] = height

            recovered_records.append(
                RecoveredRecord(
                    record_id=chunk_idx,
                    status=rec_status,
                    byte_range=(chunk_start, chunk_end),
                    fields=rec_fields,
                    errors=errors,
                )
            )
            chunk_idx += 1

            if chunk_type == "IEND":
                saw_iend = True
                break

        if not saw_iend:
            damages.append(
                DamageBlock(
                    offset=reader.position,
                    length=reader.remaining,
                    damage_type=DamageType.TRUNCATION,
                    description="PNG missing terminating IEND chunk",
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="PNG",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=len(recovered_records),
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "saw_ihdr": saw_ihdr,
                "saw_iend": saw_iend,
                "width": width,
                "height": height,
                "chunk_count": len(recovered_records),
            },
        )
