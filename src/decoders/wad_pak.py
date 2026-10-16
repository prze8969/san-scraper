"""Game Archives: Doom WAD (IWAD/PWAD) and Quake PAK (PACK) decoders."""

from __future__ import annotations
import hashlib
import struct
from typing import Any
from src.decoders.base import BaseDecoder
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult, OutputStatus, SalvagedRecord, DamageKind

class WadDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        if cursor.size < 12:
            cursor.log_damage(
                severity="TRUNCATION",
                component="header",
                message="WAD header truncated (< 12 bytes)",
                offset_start=0,
                offset_end=cursor.size,
                legacy_kind=DamageKind.TRUNCATED,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                status=OutputStatus.FAILED,
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                file_size=cursor.size,
            )

        magic, _ = cursor.read_bytes(4, component="magic")
        if magic not in (b"IWAD", b"PWAD"):
            cursor.log_damage(
                severity="ERROR",
                component="magic",
                message=f"Invalid WAD magic: {magic.hex()}",
                offset_start=0,
                offset_end=4,
                legacy_kind=DamageKind.HEADER_CHECKSUM,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                status=OutputStatus.UNRECOGNIZED,
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                file_size=cursor.size,
            )

        num_lumps, _ = cursor.read_i32_le(component="num_lumps")
        infotable_ofs, _ = cursor.read_i32_le(component="infotable_ofs")

        metadata = {
            "type": magic.decode("ascii", errors="replace"),
            "num_lumps": num_lumps,
            "directory_offset": infotable_ofs,
        }

        records: list[SalvagedRecord] = []
        status = OutputStatus.OK

        if infotable_ofs >= cursor.size or infotable_ofs < 0:
            cursor.log_damage(
                severity="OUT_OF_BOUNDS",
                component="infotable_ofs",
                message=f"Directory offset {infotable_ofs} out of bounds",
                offset_start=8,
                offset_end=12,
                legacy_kind=DamageKind.INDEX_MISSING,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                status=OutputStatus.PARTIAL,
                metadata=metadata,
                records=[],
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                file_size=cursor.size,
            )

        cursor.seek(infotable_ofs, component="seek_directory")

        for lump_idx in range(num_lumps):
            if not cursor.can_read(16):
                cursor.log_damage(
                    severity="TRUNCATION",
                    component=f"lump_entry[{lump_idx}]",
                    message="Truncated lump directory entry",
                    offset_start=cursor.pos,
                    offset_end=cursor.size,
                    legacy_kind=DamageKind.TRUNCATED,
                )
                status = OutputStatus.PARTIAL
                break

            filepos, _ = cursor.read_i32_le(component="filepos")
            size, _ = cursor.read_i32_le(component="size")
            name_raw, _ = cursor.read_bytes(8, component="name")
            name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")

            # Validate lump bounds
            if filepos < 0 or filepos > cursor.size:
                cursor.log_damage(
                    severity="OUT_OF_BOUNDS",
                    component=f"lump[{name}].offset",
                    message=f"Lump offset {filepos} out of bounds",
                    offset_start=cursor.pos - 16,
                    offset_end=cursor.pos,
                    legacy_kind=DamageKind.OOB_POINTER,
                )
                status = OutputStatus.PARTIAL
                continue

            # Read lump payload
            save_dir_pos = cursor.pos
            cursor.seek(filepos, component=f"seek_lump_{name}")
            lump_bytes, ok = cursor.read_bytes(size, component=f"lump_{name}_data", allow_partial=True)
            cursor.seek(save_dir_pos, component="restore_dir_pos")

            if not ok or len(lump_bytes) < size:
                status = OutputStatus.PARTIAL

            sha256 = hashlib.sha256(lump_bytes).hexdigest()

            records.append(
                SalvagedRecord(
                    record_id=lump_idx,
                    offset=filepos,
                    length=size,
                    status="VERIFIED" if ok else "SALVAGED_PARTIAL",
                    record_type="WAD_LUMP",
                    fields={
                        "name": name,
                        "offset": filepos,
                        "size": size,
                        "sha256": sha256,
                    },
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="WAD",
            status=status,
            metadata=metadata,
            records=records,
            damages=cursor.legacy_damages,
            damage_events=cursor.damages,
            file_size=cursor.size,
            unclaimed_byte_ranges=cursor.get_unclaimed_ranges(),
            coverage_ratio=cursor.coverage_ratio(),
        )


class PakDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        if cursor.size < 12:
            cursor.log_damage(
                severity="TRUNCATION",
                component="header",
                message="PAK header truncated (< 12 bytes)",
                offset_start=0,
                offset_end=cursor.size,
                legacy_kind=DamageKind.TRUNCATED,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                status=OutputStatus.FAILED,
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                file_size=cursor.size,
            )

        magic, _ = cursor.read_bytes(4, component="magic")
        if magic != b"PACK":
            cursor.log_damage(
                severity="ERROR",
                component="magic",
                message=f"Invalid PAK magic: {magic.hex()}",
                offset_start=0,
                offset_end=4,
                legacy_kind=DamageKind.HEADER_CHECKSUM,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                status=OutputStatus.UNRECOGNIZED,
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                file_size=cursor.size,
            )

        dirofs, _ = cursor.read_i32_le(component="dirofs")
        dirlen, _ = cursor.read_i32_le(component="dirlen")

        entry_count = dirlen // 64 if dirlen >= 0 else 0
        metadata = {
            "directory_offset": dirofs,
            "directory_length": dirlen,
            "entry_count": entry_count,
        }

        records: list[SalvagedRecord] = []
        status = OutputStatus.OK

        if dirofs >= cursor.size or dirofs < 0 or dirofs + dirlen > cursor.size:
            cursor.log_damage(
                severity="OUT_OF_BOUNDS",
                component="dirofs",
                message=f"Directory slice [{dirofs}:{dirofs + dirlen}] out of bounds",
                offset_start=4,
                offset_end=12,
                legacy_kind=DamageKind.INDEX_MISSING,
            )
            status = OutputStatus.PARTIAL
            if dirofs >= cursor.size or dirofs < 0:
                return FileRecoveryResult(
                    filename=filename,
                    format_name="PAK",
                    status=status,
                    metadata=metadata,
                    records=[],
                    damages=cursor.legacy_damages,
                    damage_events=cursor.damages,
                    file_size=cursor.size,
                )

        cursor.seek(dirofs, component="seek_directory")

        for entry_idx in range(entry_count):
            if not cursor.can_read(64):
                cursor.log_damage(
                    severity="TRUNCATION",
                    component=f"pak_entry[{entry_idx}]",
                    message="Truncated PAK directory entry",
                    offset_start=cursor.pos,
                    offset_end=cursor.size,
                    legacy_kind=DamageKind.TRUNCATED,
                )
                status = OutputStatus.PARTIAL
                break

            name_raw, _ = cursor.read_bytes(56, component="name")
            name = name_raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
            filepos, _ = cursor.read_i32_le(component="filepos")
            filelen, _ = cursor.read_i32_le(component="filelen")

            if filepos < 0 or filepos > cursor.size:
                cursor.log_damage(
                    severity="OUT_OF_BOUNDS",
                    component=f"file[{name}].offset",
                    message=f"File offset {filepos} out of bounds",
                    offset_start=cursor.pos - 8,
                    offset_end=cursor.pos,
                    legacy_kind=DamageKind.OOB_POINTER,
                )
                status = OutputStatus.PARTIAL
                continue

            save_dir_pos = cursor.pos
            cursor.seek(filepos, component=f"seek_pak_{name}")
            file_bytes, ok = cursor.read_bytes(filelen, component=f"pak_{name}_data", allow_partial=True)
            cursor.seek(save_dir_pos, component="restore_dir_pos")

            if not ok or len(file_bytes) < filelen:
                status = OutputStatus.PARTIAL

            sha256 = hashlib.sha256(file_bytes).hexdigest()

            records.append(
                SalvagedRecord(
                    record_id=entry_idx,
                    offset=filepos,
                    length=filelen,
                    status="VERIFIED" if ok else "SALVAGED_PARTIAL",
                    record_type="PAK_ENTRY",
                    fields={
                        "name": name,
                        "offset": filepos,
                        "size": filelen,
                        "sha256": sha256,
                    },
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="PAK",
            status=status,
            metadata=metadata,
            records=records,
            damages=cursor.legacy_damages,
            damage_events=cursor.damages,
            file_size=cursor.size,
            unclaimed_byte_ranges=cursor.get_unclaimed_ranges(),
            coverage_ratio=cursor.coverage_ratio(),
        )
