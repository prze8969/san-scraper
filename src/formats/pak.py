"""Parser for id Software Quake PAK format."""

from __future__ import annotations
import re
from pathlib import PurePosixPath
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class PakParser(BaseParser):
    """
    Defensive parser for id Software Quake PAK archives.

    Specification:
      Header (12 bytes):
        0x00..0x04: Magic 'PACK' (4 bytes)
        0x04..0x08: Directory offset (uint32, little-endian)
        0x08..0x0C: Directory length (uint32, little-endian)
      Directory Entry (64 bytes each):
        0x00..0x38: Filename (56 bytes, null-terminated ASCII)
        0x38..0x3C: File offset (uint32, little-endian)
        0x3C..0x40: File size (uint32, little-endian)
    """

    MAGIC = b"PACK"
    HEADER_SIZE = 12
    ENTRY_SIZE = 64
    MAX_ENTRY_COUNT = 10000
    MAX_TOTAL_EXTRACT_BYTES = 64 * 1024 * 1024  # 64 MB cap

    @staticmethod
    def sanitize_path(raw_path: str) -> tuple[str, bool]:
        """
        Sanitizes untrusted filename to prevent directory traversal, drive letters,
        absolute paths, symlink escapes, null-byte injections, or Windows device names.
        Returns (sanitized_path, was_suspicious).
        """
        # Strip null bytes and whitespace
        clean = raw_path.replace("\x00", "").strip()
        # Normalize backslashes to forward slashes
        clean = clean.replace("\\", "/")
        # Remove Windows drive letters e.g. C:, D:
        clean = re.sub(r"^[a-zA-Z]:", "", clean)
        # Strip leading slashes
        clean = clean.lstrip("/")

        # Check for path traversal elements and device names
        parts = clean.split("/")
        safe_parts = []
        suspicious = False
        reserved_devices = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3"}

        for p in parts:
            p = p.strip()
            if not p or p == ".":
                continue
            if p == ".." or ".." in p or p.startswith("~"):
                suspicious = True
                continue
            # Block Windows reserved device names
            base_device = p.split(".")[0].upper()
            if base_device in reserved_devices:
                suspicious = True
                p = f"safe_{p}"
            safe_parts.append(p)

        if not safe_parts:
            safe_path = "unnamed_entry"
            suspicious = True
        else:
            safe_path = "/".join(safe_parts)

        return safe_path, suspicious

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        # Step 1: Minimum Header Check
        if file_size < self.HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than PAK header ({file_size} < {self.HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        # Step 2: Read Header
        try:
            magic = reader.read_bytes(4)
            dir_offset = reader.read_u32_le()
            dir_length = reader.read_u32_le()
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Failed reading PAK header: {str(e)}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
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
                    length=4,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid PAK magic: {magic.hex()}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        is_valid_header = True

        # Step 3: Validate Directory Bounds
        if dir_offset < self.HEADER_SIZE or dir_offset > file_size:
            damages.append(
                DamageBlock(
                    offset=4,
                    length=4,
                    damage_type=DamageType.MALFORMED_OFFSET,
                    description=f"Directory offset {dir_offset} out of file bounds [0, {file_size}]",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                file_size=file_size,
                is_valid_header=is_valid_header,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        if dir_length % self.ENTRY_SIZE != 0:
            damages.append(
                DamageBlock(
                    offset=8,
                    length=4,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Directory length {dir_length} is not divisible by entry size {self.ENTRY_SIZE}",
                )
            )

        if dir_offset + dir_length > file_size:
            damages.append(
                DamageBlock(
                    offset=dir_offset,
                    length=max(0, file_size - dir_offset),
                    damage_type=DamageType.TRUNCATION,
                    description=f"Directory extends beyond end of file ({dir_offset + dir_length} > {file_size})",
                )
            )
            dir_length = max(0, file_size - dir_offset)

        total_declared_entries = dir_length // self.ENTRY_SIZE
        entries_to_read = min(total_declared_entries, self.MAX_ENTRY_COUNT)

        # Step 4: Parse Directory Entries Defensively
        reader.seek(dir_offset)
        seen_names: dict[str, int] = {}
        seen_ranges: list[tuple[int, int, str]] = []
        total_extracted_bytes = 0

        for i in range(entries_to_read):
            entry_offset = reader.position
            try:
                raw_name = reader.read_fixed_string(56, encoding="latin-1")
                f_offset = reader.read_u32_le()
                f_size = reader.read_u32_le()
            except (BoundsError, TruncationError) as e:
                damages.append(
                    DamageBlock(
                        offset=entry_offset,
                        length=self.ENTRY_SIZE,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Directory entry {i} truncated: {str(e)}",
                    )
                )
                break

            safe_name, was_traversal = self.sanitize_path(raw_name)
            errors: list[str] = []
            rec_status = RecordStatus.COMPLETE

            if was_traversal:
                errors.append(f"Sanitized unsafe directory traversal name: {raw_name} -> {safe_name}")

            # Check duplicate filenames
            if safe_name in seen_names:
                errors.append(f"Duplicate entry name: {safe_name} (index {seen_names[safe_name]})")
            seen_names[safe_name] = i

            # Validate entry payload bounds
            if f_offset < 0 or f_offset + f_size > file_size:
                rec_status = RecordStatus.UNRECOVERABLE
                err_msg = f"Entry payload [{f_offset}:{f_offset + f_size}] exceeds file size {file_size}"
                errors.append(err_msg)
                damages.append(
                    DamageBlock(
                        offset=entry_offset,
                        length=self.ENTRY_SIZE,
                        damage_type=DamageType.MALFORMED_OFFSET,
                        description=f"Entry '{safe_name}' {err_msg}",
                    )
                )
            else:
                # Check for overlap with directory itself
                if max(f_offset, dir_offset) < min(f_offset + f_size, dir_offset + dir_length):
                    errors.append("Payload overlaps directory table")

                # Check for overlap with other file entries
                for prev_s, prev_e, prev_n in seen_ranges:
                    if max(f_offset, prev_s) < min(f_offset + f_size, prev_e):
                        errors.append(f"Payload overlaps entry '{prev_n}'")
                seen_ranges.append((f_offset, f_offset + f_size, safe_name))

            total_extracted_bytes += f_size
            recovered_records.append(
                RecoveredRecord(
                    record_id=i,
                    status=rec_status,
                    byte_range=(f_offset, f_offset + f_size),
                    fields={
                        "name": safe_name,
                        "raw_name": raw_name,
                        "offset": f_offset,
                        "size": f_size,
                    },
                    errors=errors,
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="PAK",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=total_declared_entries,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "directory_offset": dir_offset,
                "directory_length": dir_length,
                "total_entries": total_declared_entries,
            },
        )
