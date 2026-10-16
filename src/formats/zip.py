"""Parser for standard ZIP archives with local header fallback recovery.

Specification:
  Local File Header:
    0x00..0x04: Signature b'PK\\x03\\x04'
    0x04..0x06: Version needed to extract (uint16)
    0x06..0x08: General purpose bit flag (uint16)
    0x08..0x0A: Compression method (uint16: 0=stored, 8=deflated)
    0x0A..0x0E: Last mod file time/date (uint32)
    0x0E..0x12: CRC-32 (uint32)
    0x12..0x16: Compressed size (uint32)
    0x16..0x1A: Uncompressed size (uint32)
    0x1A..0x1C: Filename length N (uint16)
    0x1C..0x1E: Extra field length M (uint16)
    Followed by N bytes filename, M bytes extra field, then compressed data.
  End of Central Directory Record (EOCD):
    0x00..0x04: Signature b'PK\\x05\\x06'
"""

from __future__ import annotations
import re
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

class ZipParser(BaseParser):
    """Defensive parser for ZIP archives supporting central directory and local header recovery."""

    LOCAL_HEADER_SIG = b"PK\x03\x04"
    CENTRAL_DIR_SIG = b"PK\x01\x02"
    EOCD_SIG = b"PK\x05\x06"
    MAX_DECOMPRESSED_PER_ENTRY = 16 * 1024 * 1024  # 16 MB bomb cap
    MAX_ENTRIES = 10000

    @staticmethod
    def sanitize_name(name: str) -> tuple[str, bool]:
        clean = name.replace("\x00", "").replace("\\", "/").strip().lstrip("/")
        parts = [p for p in clean.split("/") if p and p != "."]
        was_traversal = any(p == ".." or ".." in p for p in parts)
        safe_parts = [p for p in parts if p != ".." and not p.startswith("~")]
        if not safe_parts:
            return "unnamed_entry", was_traversal
        return "/".join(safe_parts), was_traversal

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        if file_size < 22:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum ZIP boundary ({file_size} < 22)",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="ZIP",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                damages=damages,
            )

        data = reader.peek_bytes(file_size)
        has_local_0 = data.startswith(self.LOCAL_HEADER_SIG)
        eocd_pos = data.rfind(self.EOCD_SIG)

        if has_local_0:
            is_valid_header = True

        # Scan for local file headers throughout the buffer
        # This provides robust recovery even if central directory is truncated or damaged
        local_header_offsets = []
        idx = 0
        while len(local_header_offsets) < self.MAX_ENTRIES:
            pos = data.find(self.LOCAL_HEADER_SIG, idx)
            if pos == -1:
                break
            local_header_offsets.append(pos)
            idx = pos + 4

        seen_names: dict[str, int] = {}
        entry_idx = 0

        for off in local_header_offsets:
            if off + 30 > file_size:
                damages.append(
                    DamageBlock(
                        offset=off,
                        length=file_size - off,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Local header at {off} truncated before standard 30-byte header",
                    )
                )
                break

            try:
                (
                    sig,
                    ver,
                    flags,
                    method,
                    mod_time,
                    mod_date,
                    crc32_val,
                    comp_size,
                    uncomp_size,
                    name_len,
                    extra_len,
                ) = struct.unpack("<4sHHHHHIIIHH", data[off : off + 30])
            except Exception as e:
                damages.append(
                    DamageBlock(
                        offset=off,
                        length=30,
                        damage_type=DamageType.CORRUPT_RECORD,
                        description=f"Malformed local header at {off}: {str(e)}",
                    )
                )
                continue

            name_start = off + 30
            extra_start = name_start + name_len
            data_start = extra_start + extra_len

            if data_start > file_size:
                damages.append(
                    DamageBlock(
                        offset=off,
                        length=file_size - off,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Header fields at offset {off} point past file end",
                    )
                )
                break

            raw_name = data[name_start:extra_start].decode("latin-1", errors="replace")
            safe_name, was_traversal = self.sanitize_name(raw_name)

            errors: list[str] = []
            if was_traversal:
                errors.append(f"Sanitized traversal path: {raw_name} -> {safe_name}")

            if safe_name in seen_names:
                errors.append(f"Duplicate entry name: {safe_name}")
            seen_names[safe_name] = entry_idx

            data_end = data_start + comp_size
            rec_status = RecordStatus.COMPLETE
            decompressed_payload: bytes | None = None

            if data_end > file_size:
                rec_status = RecordStatus.PARTIAL
                errors.append(f"Compressed payload truncated: needs {comp_size}B, only {file_size - data_start}B left")
                damages.append(
                    DamageBlock(
                        offset=data_start,
                        length=file_size - data_start,
                        damage_type=DamageType.TRUNCATION,
                        description=f"ZIP payload for '{safe_name}' truncated",
                    )
                )
                data_end = file_size
                compressed_slice = data[data_start:data_end]
            else:
                compressed_slice = data[data_start:data_end]

            # Attempt verified decompression if stored (0) or deflate (8)
            crc_status = "unverified"
            if method == 0:  # Stored
                decompressed_payload = compressed_slice
                calc_crc = zlib.crc32(decompressed_payload) & 0xFFFFFFFF
                if crc32_val != 0 and calc_crc != crc32_val:
                    crc_status = "mismatch"
                    errors.append(f"Stored CRC32 mismatch: declared 0x{crc32_val:08X}, got 0x{calc_crc:08X}")
                    rec_status = RecordStatus.CORRUPTED
                else:
                    crc_status = "verified"
            elif method == 8:  # Deflate
                if uncomp_size > self.MAX_DECOMPRESSED_PER_ENTRY:
                    errors.append(f"Decompressed size {uncomp_size} exceeds safety cap {self.MAX_DECOMPRESSED_PER_ENTRY}")
                    rec_status = RecordStatus.PARTIAL
                else:
                    try:
                        # raw deflate stream (-15 window bits)
                        decompressed_payload = zlib.decompress(compressed_slice, -15, self.MAX_DECOMPRESSED_PER_ENTRY)
                        calc_crc = zlib.crc32(decompressed_payload) & 0xFFFFFFFF
                        if crc32_val != 0 and calc_crc != crc32_val:
                            crc_status = "mismatch"
                            errors.append(f"CRC32 mismatch: declared 0x{crc32_val:08X}, got 0x{calc_crc:08X}")
                            rec_status = RecordStatus.CORRUPTED
                        else:
                            crc_status = "verified"
                    except Exception as e:
                        errors.append(f"Deflate decompression error: {str(e)}")
                        rec_status = RecordStatus.CORRUPTED
                        damages.append(
                            DamageBlock(
                                offset=data_start,
                                length=len(compressed_slice),
                                damage_type=DamageType.DECOMPRESSION_ERROR,
                                description=f"Deflate failed for '{safe_name}': {str(e)}",
                            )
                        )
            else:
                errors.append(f"Unsupported compression method {method}")
                rec_status = RecordStatus.PARTIAL

            rec_fields = {
                "name": safe_name,
                "raw_name": raw_name,
                "offset": data_start,
                "compressed_size": comp_size,
                "uncompressed_size": uncomp_size,
                "method": "deflate" if method == 8 else ("stored" if method == 0 else f"method_{method}"),
                "crc32": f"0x{crc32_val:08X}",
                "crc_status": crc_status,
            }
            if decompressed_payload is not None and rec_status in (RecordStatus.COMPLETE, RecordStatus.PARTIAL):
                rec_fields["decompressed_data"] = decompressed_payload

            recovered_records.append(
                RecoveredRecord(
                    record_id=entry_idx,
                    status=rec_status,
                    byte_range=(off, data_end),
                    fields=rec_fields,
                    errors=errors,
                )
            )
            entry_idx += 1

        if eocd_pos == -1 and local_header_offsets:
            damages.append(
                DamageBlock(
                    offset=max(0, file_size - 64),
                    length=min(64, file_size),
                    damage_type=DamageType.TRUNCATION,
                    description="Missing or truncated End of Central Directory (EOCD)",
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="ZIP",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=len(recovered_records),
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "has_eocd": (eocd_pos != -1),
                "recovered_entries": len(recovered_records),
            },
        )
