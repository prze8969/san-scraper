"""Parser for id Software Doom WAD format (IWAD and PWAD).

Specification:
  Header (12 bytes):
    0x00..0x04: Magic 'IWAD' or 'PWAD' (4 bytes)
    0x04..0x08: Number of lumps (uint32, little-endian)
    0x08..0x0C: Lump directory offset (uint32, little-endian)
  Lump Directory Entry (16 bytes each):
    0x00..0x04: Lump file offset (uint32, little-endian)
    0x04..0x08: Lump size (uint32, little-endian)
    0x08..0x10: Lump name (8 bytes, ASCII null-padded)
"""

from __future__ import annotations
import re
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class WadParser(BaseParser):
    """Defensive parser for Doom WAD archives (IWAD/PWAD)."""

    IWAD_MAGIC = b"IWAD"
    PWAD_MAGIC = b"PWAD"
    HEADER_SIZE = 12
    ENTRY_SIZE = 16
    MAX_LUMPS = 50000

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        if file_size < self.HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than WAD header ({file_size} < {self.HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        try:
            magic = reader.read_bytes(4)
            num_lumps = reader.read_u32_le()
            dir_offset = reader.read_u32_le()
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Failed reading WAD header: {str(e)}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        if magic not in (self.IWAD_MAGIC, self.PWAD_MAGIC):
            damages.append(
                DamageBlock(
                    offset=0,
                    length=4,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid WAD magic: {magic.hex()}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        is_valid_header = True
        wad_type = "IWAD" if magic == self.IWAD_MAGIC else "PWAD"

        # Check directory bounds
        expected_dir_size = num_lumps * self.ENTRY_SIZE
        if dir_offset < self.HEADER_SIZE or dir_offset > file_size:
            damages.append(
                DamageBlock(
                    offset=8,
                    length=4,
                    damage_type=DamageType.MALFORMED_OFFSET,
                    description=f"Lump directory offset {dir_offset} out of bounds [0, {file_size}]",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                file_size=file_size,
                is_valid_header=is_valid_header,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"wad_type": wad_type},
            )

        actual_dir_capacity = max(0, (file_size - dir_offset) // self.ENTRY_SIZE)
        if actual_dir_capacity < num_lumps:
            damages.append(
                DamageBlock(
                    offset=dir_offset,
                    length=file_size - dir_offset,
                    damage_type=DamageType.TRUNCATION,
                    description=f"Directory truncated: declared {num_lumps} lumps, space for {actual_dir_capacity}",
                )
            )
            lumps_to_read = min(actual_dir_capacity, self.MAX_LUMPS)
        else:
            lumps_to_read = min(num_lumps, self.MAX_LUMPS)

        reader.seek(dir_offset)
        seen_names: dict[str, int] = {}

        for i in range(lumps_to_read):
            entry_offset = reader.position
            try:
                lump_offset = reader.read_u32_le()
                lump_size = reader.read_u32_le()
                name_bytes = reader.read_bytes(8)
            except BoundsError as e:
                damages.append(
                    DamageBlock(
                        offset=entry_offset,
                        length=self.ENTRY_SIZE,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Directory entry {i} truncated: {str(e)}",
                    )
                )
                break

            # ASCII null-padded name up to 8 chars
            name = name_bytes.split(b"\x00", 1)[0].decode("latin-1", errors="replace").strip()
            # Sanitize name
            safe_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", name) or f"lump_{i}"

            errors: list[str] = []
            rec_status = RecordStatus.COMPLETE

            if safe_name in seen_names:
                errors.append(f"Duplicate lump name '{safe_name}' (first at #{seen_names[safe_name]})")
            seen_names[safe_name] = i

            # Marker lumps (size == 0) are valid in WADs (e.g. F_START, S_END, P_START)
            if lump_size == 0:
                rec_status = RecordStatus.COMPLETE
                start_b = lump_offset
                end_b = lump_offset
            elif lump_offset < 0 or lump_offset + lump_size > file_size:
                rec_status = RecordStatus.UNRECOVERABLE
                err_msg = f"Lump [{lump_offset}:{lump_offset+lump_size}] exceeds file size {file_size}"
                errors.append(err_msg)
                damages.append(
                    DamageBlock(
                        offset=entry_offset,
                        length=self.ENTRY_SIZE,
                        damage_type=DamageType.MALFORMED_OFFSET,
                        description=f"Lump '{safe_name}' {err_msg}",
                    )
                )
                start_b = lump_offset
                end_b = min(file_size, max(0, lump_offset + lump_size))
            else:
                start_b = lump_offset
                end_b = lump_offset + lump_size

            recovered_records.append(
                RecoveredRecord(
                    record_id=i,
                    status=rec_status,
                    byte_range=(start_b, end_b),
                    fields={
                        "name": safe_name,
                        "raw_name": name,
                        "offset": lump_offset,
                        "size": lump_size,
                        "is_marker": (lump_size == 0),
                    },
                    errors=errors,
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="WAD",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=num_lumps,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "wad_type": wad_type,
                "directory_offset": dir_offset,
                "declared_lumps": num_lumps,
                "recovered_lumps": len(recovered_records),
            },
        )
