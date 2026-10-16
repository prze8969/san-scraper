"""Parser for id Software Quake PAK format conforming to OUTPUT-CONTRACT.md.
Verified against s24.pak.
"""

from __future__ import annotations
import struct
import hashlib
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class PakParser(BaseParser):
    MAGIC = b"PACK"

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 12:
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                status=OutputStatus.FAILED,
                damages=[DamageItem(kind=DamageKind.TRUNCATED, offset=0, detail="Header truncated", lossy=True)],
            )

        magic = data[:4]
        if magic != self.MAGIC:
            return FileRecoveryResult(
                filename=filename,
                format_name="PAK",
                status=OutputStatus.UNRECOGNIZED,
                damages=[DamageItem(kind=DamageKind.HEADER_CHECKSUM, offset=0, detail="Invalid PAK magic", lossy=True)],
            )

        dir_offset, dir_len = struct.unpack("<II", data[4:12])
        num_files = dir_len // 64
        metadata = {
            "dir_offset": dir_offset,
            "dir_length": dir_len,
            "file_count": num_files,
        }

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        if dir_offset + dir_len > len(data):
            status = OutputStatus.PARTIAL
            dmg_kind = DamageKind.OOB_POINTER if dir_offset > len(data) else DamageKind.TRUNCATED
            damages.append(
                DamageItem(
                    kind=dmg_kind,
                    offset=dir_offset,
                    detail="PAK directory table out of bounds or truncated",
                    lossy=True,
                )
            )
            avail_entries = max(0, (len(data) - dir_offset) // 64)
        else:
            avail_entries = num_files

        for i in range(avail_entries):
            e_off = dir_offset + i * 64
            raw_name = data[e_off:e_off+56].rstrip(b"\x00").decode("ascii", errors="replace")
            f_off, f_sz = struct.unpack("<II", data[e_off+56:e_off+64])

            if f_off + f_sz > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=f_off,
                        detail=f"Entry '{raw_name}' payload truncated",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                payload = data[f_off:] if f_off < len(data) else b""
            else:
                payload = data[f_off:f_off+f_sz]

            sha256 = hashlib.sha256(payload).hexdigest()
            records.append({
                "name": raw_name,
                "offset": f_off,
                "size": f_sz,
                "sha256": sha256,
            })

        return FileRecoveryResult(
            filename=filename,
            format_name="PAK",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
