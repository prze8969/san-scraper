"""Provisional parser for LIBRA-98 format."""

from __future__ import annotations
import zlib
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class Libra98Parser(BaseParser):
    """
    Defensive parser for LIBRA-98 files.
    
    Layout contract (PROVISIONAL - for defensive testing and recovery engine validation):
    Header (32 bytes):
      0x00..0x08: Magic 'LIBRA98\x00' (or 'LIB98\x00\x00\x00')
      0x08..0x0A: Version (uint16)
      0x0A..0x0C: Flags (uint16)
      0x0C..0x10: Header size (uint32)
      0x10..0x14: Record count (uint32)
      0x14..0x18: Record size (uint32)
      0x18..0x1C: Header CRC32 (uint32)
      0x1C..0x20: Reserved (4 bytes)
    
    Record (48 bytes default):
      +0x00: Record ID (uint32)
      +0x04: Timestamp (uint32)
      +0x08: Status flag (uint16)
      +0x0A: Numeric Value (int32)
      +0x0E: Label (30 bytes, null-terminated)
      +0x2C: Record CRC16 / Checksum (uint16)
      +0x2E: Reserved (uint16)
    """

    MAGIC_LONG = b"LIBRA98\x00"
    MAGIC_SHORT = b"LIB98\x00"
    MIN_HEADER_SIZE = 32
    DEFAULT_RECORD_SIZE = 48

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False
        declared_records = 0

        # Step 1: Validate Header Size
        if file_size < self.MIN_HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum header size ({file_size} < {self.MIN_HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LIBRA-98",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        # Step 2: Read Header
        try:
            magic = reader.read_bytes(8)
            version = reader.read_u16_le()
            flags = reader.read_u16_le()
            header_size = reader.read_u32_le()
            declared_records = reader.read_u32_le()
            record_size = reader.read_u32_le()
            header_crc = reader.read_u32_le()
            _reserved = reader.read_bytes(4)
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Header read failed: {str(e)}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LIBRA-98",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        # Validate declared sizes to prevent out-of-bounds or invalid seek
        if header_size < self.MIN_HEADER_SIZE or header_size > file_size:
            damages.append(
                DamageBlock(
                    offset=0x0C,
                    length=4,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Invalid header_size declared: {header_size} (file size {file_size})",
                )
            )
            header_size = self.MIN_HEADER_SIZE

        # Bound record_size to safe reasonable range
        if record_size < 16 or record_size > 65536:
            damages.append(
                DamageBlock(
                    offset=0x14,
                    length=4,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Invalid record_size declared: {record_size}, defaulting to {self.DEFAULT_RECORD_SIZE}",
                )
            )
            record_size = self.DEFAULT_RECORD_SIZE

        # Validate Magic
        if magic != self.MAGIC_LONG:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=8,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid LIBRA-98 magic: {magic.hex()}",
                )
            )
        else:
            is_valid_header = True

        # Header Checksum Validation
        expected_crc = zlib.crc32(reader.read_exact(24, 0)) & 0xFFFFFFFF
        if header_crc != 0 and header_crc != expected_crc:
            damages.append(
                DamageBlock(
                    offset=0x18,
                    length=4,
                    damage_type=DamageType.CHECKSUM_MISMATCH,
                    description=f"Header CRC mismatch: declared 0x{header_crc:08X}, calculated 0x{expected_crc:08X}",
                )
            )

        # Step 3: Parse Records Defensively
        reader.seek(header_size)

        # Strictly bound records to prevent runaway loops or memory exhaustion
        max_possible_records = (file_size - reader.position) // record_size
        records_to_attempt = min(declared_records, max_possible_records) if declared_records > 0 else max_possible_records

        rec_idx = 0
        while rec_idx < records_to_attempt and reader.remaining >= record_size:
            rec_start = reader.position
            try:
                rec_id = reader.read_u32_le()
                timestamp = reader.read_u32_le()
                status_flag = reader.read_u16_le()
                numeric_val = reader.read_i32_le()
                label = reader.read_fixed_string(30)
                rec_crc = reader.read_u16_le()
                reader.read_u16_le()  # padding
                rec_end = reader.position

                # Check record CRC16
                calc_crc16 = zlib.crc32(reader.read_exact(44, rec_start)) & 0xFFFF
                rec_status = RecordStatus.COMPLETE
                errs = []

                if rec_crc != 0 and rec_crc != calc_crc16:
                    rec_status = RecordStatus.CORRUPTED
                    errs.append(f"Record CRC mismatch (declared: 0x{rec_crc:04X}, calculated: 0x{calc_crc16:04X})")
                    damages.append(
                        DamageBlock(
                            offset=rec_start,
                            length=record_size,
                            damage_type=DamageType.CORRUPT_RECORD,
                            description=f"Record {rec_id} checksum failed",
                        )
                    )

                recovered_records.append(
                    RecoveredRecord(
                        record_id=rec_id,
                        status=rec_status,
                        byte_range=(rec_start, rec_end),
                        fields={
                            "timestamp": timestamp,
                            "status_flags": status_flag,
                            "value": numeric_val,
                            "label": label,
                        },
                        errors=errs,
                    )
                )
                rec_idx += 1

            except (BoundsError, TruncationError) as e:
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=reader.remaining,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Record {rec_idx} truncated: {str(e)}",
                    )
                )
                break

        # Check for unaligned trailing bytes
        if reader.remaining > 0:
            damages.append(
                DamageBlock(
                    offset=reader.position,
                    length=reader.remaining,
                    damage_type=DamageType.TRUNCATION,
                    description=f"Unparsed trailing bytes ({reader.remaining} bytes)",
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="LIBRA-98",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=declared_records,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "version": version if is_valid_header else None,
                "flags": flags if is_valid_header else None,
            },
        )
