"""Provisional parser for LABLOG format with per-block checksum validation and damage isolation."""

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

class LablogParser(BaseParser):
    """
    Defensive parser for LABLOG journal files.

    Layout contract (PROVISIONAL - for defensive testing and block isolation validation):
    Header (24 bytes):
      0x00..0x08: Magic 'LABLOG\x01\x00' (8 bytes)
      0x08..0x0A: Version (uint16, expected 1)
      0x0A..0x0C: Declared Block Count (uint16)
      0x0C..0x10: Header Checksum CRC32 (uint32 over bytes 0..11)
      0x10..0x18: Created Timestamp (uint64)

    Block Frame (min 24 bytes + payload):
      +0x00..+0x04: Sync Magic 'BLOK' (4 bytes)
      +0x04..+0x08: Block Sequence ID (uint32)
      +0x08..+0x0A: Block Type / Severity (uint16)
      +0x0A..0x0C: Flags (uint16)
      +0x0C..+0x10: Payload Length N (uint32)
      +0x10..+0x14: Payload CRC32 (uint32)
      +0x14..+0x18: Timestamp (uint32)
      +0x18..+0x18+N: Payload Data
    """

    MAGIC = b"LABLOG\x01\x00"
    BLOCK_MAGIC = b"BLOK"
    HEADER_SIZE = 24
    BLOCK_HEADER_SIZE = 24
    MAX_PAYLOAD_SIZE = 16 * 1024 * 1024  # 16 MB allocation cap per block

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False
        declared_blocks = 0
        version = None

        # Step 1: Validate Header Size
        if file_size < self.HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum LABLOG header ({file_size} < {self.HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
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
            declared_blocks = reader.read_u16_le()
            header_crc = reader.read_u32_le()
            created_ts = reader.read_u64_le()
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Header read error: {str(e)}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        if magic != self.MAGIC:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=8,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid LABLOG magic bytes: {magic.hex()}",
                )
            )
        else:
            is_valid_header = True

        # Header CRC Check
        expected_header_crc = zlib.crc32(reader.read_exact(12, 0)) & 0xFFFFFFFF
        if header_crc != 0 and header_crc != expected_header_crc:
            damages.append(
                DamageBlock(
                    offset=0x0C,
                    length=4,
                    damage_type=DamageType.CHECKSUM_MISMATCH,
                    description=f"Header CRC mismatch: declared 0x{header_crc:08X}, calculated 0x{expected_header_crc:08X}",
                )
            )

        # Step 3: Iterate Blocks with Damage Isolation & Boundary Resynchronization
        block_idx = 0
        while reader.remaining >= self.BLOCK_HEADER_SIZE:
            block_start = reader.position

            # Verify 'BLOK' sync marker
            sync = reader.peek_bytes(4)
            if sync != self.BLOCK_MAGIC:
                # Malformed frame: attempt resynchronization by scanning forward for next 'BLOK'
                search_data = reader.peek_bytes(reader.remaining)
                next_sync_idx = search_data.find(self.BLOCK_MAGIC, 1)
                if next_sync_idx != -1:
                    unrec_len = next_sync_idx
                    damages.append(
                        DamageBlock(
                            offset=block_start,
                            length=unrec_len,
                            damage_type=DamageType.CORRUPT_RECORD,
                            description=f"Malformed block at offset {block_start}: desynchronized {unrec_len} bytes",
                        )
                    )
                    reader.skip(unrec_len)
                    continue
                else:
                    # No more sync markers found; record remaining bytes as unrecoverable
                    damages.append(
                        DamageBlock(
                            offset=block_start,
                            length=reader.remaining,
                            damage_type=DamageType.CORRUPT_RECORD,
                            description=f"Unrecoverable trailing data ({reader.remaining} bytes) without BLOK sync",
                        )
                    )
                    reader.skip(reader.remaining)
                    break

            # Read Block Frame Header
            try:
                _sync = reader.read_bytes(4)
                seq_id = reader.read_u32_le()
                blk_type = reader.read_u16_le()
                flags = reader.read_u16_le()
                payload_len = reader.read_u32_le()
                declared_crc = reader.read_u32_le()
                timestamp = reader.read_u32_le()
            except (BoundsError, TruncationError) as e:
                damages.append(
                    DamageBlock(
                        offset=block_start,
                        length=reader.remaining,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Truncated block header: {str(e)}",
                    )
                )
                break

            # Validate declared payload length against defensive limits
            if payload_len > self.MAX_PAYLOAD_SIZE:
                damages.append(
                    DamageBlock(
                        offset=block_start + 12,
                        length=4,
                        damage_type=DamageType.INVALID_HEADER,
                        description=f"Block {seq_id} payload length {payload_len} exceeds maximum allocation cap",
                    )
                )
                # Resync to next block
                continue

            # Check if payload is truncated
            if reader.remaining < payload_len:
                avail = reader.remaining
                partial_payload = reader.read_bytes(avail)
                damages.append(
                    DamageBlock(
                        offset=reader.position - avail,
                        length=avail,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Block {seq_id} payload truncated (expected {payload_len}, got {avail})",
                    )
                )
                recovered_records.append(
                    RecoveredRecord(
                        record_id=seq_id,
                        status=RecordStatus.PARTIAL,
                        byte_range=(block_start, reader.position),
                        fields={
                            "block_type": blk_type,
                            "flags": flags,
                            "timestamp": timestamp,
                            "payload_text": partial_payload.decode("utf-8", errors="replace"),
                            "declared_len": payload_len,
                            "actual_len": avail,
                        },
                        errors=["Truncated payload"],
                    )
                )
                break

            # Read full payload and verify Checksum
            payload_bytes = reader.read_bytes(payload_len)
            calc_crc = zlib.crc32(payload_bytes) & 0xFFFFFFFF
            block_end = reader.position

            errors = []
            rec_status = RecordStatus.COMPLETE
            if declared_crc != 0 and declared_crc != calc_crc:
                rec_status = RecordStatus.CORRUPTED
                err_msg = f"Block {seq_id} CRC mismatch (declared 0x{declared_crc:08X}, calculated 0x{calc_crc:08X})"
                errors.append(err_msg)
                damages.append(
                    DamageBlock(
                        offset=block_start + 16,
                        length=4,
                        damage_type=DamageType.CHECKSUM_MISMATCH,
                        description=err_msg,
                    )
                )

            recovered_records.append(
                RecoveredRecord(
                    record_id=seq_id,
                    status=rec_status,
                    byte_range=(block_start, block_end),
                    fields={
                        "block_type": blk_type,
                        "flags": flags,
                        "timestamp": timestamp,
                        "payload_text": payload_bytes.decode("utf-8", errors="replace"),
                        "payload_len": payload_len,
                    },
                    errors=errors,
                )
            )
            block_idx += 1

        # Check for unaligned trailing bytes
        if reader.remaining > 0:
            damages.append(
                DamageBlock(
                    offset=reader.position,
                    length=reader.remaining,
                    damage_type=DamageType.TRUNCATION,
                    description=f"Trailing unparsed bytes at end of LABLOG ({reader.remaining} bytes)",
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="LABLOG",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=declared_blocks,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "version": version if is_valid_header else None,
                "created_timestamp": created_ts if is_valid_header else None,
            },
        )
