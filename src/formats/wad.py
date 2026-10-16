"""Doom WAD format parser conforming to OUTPUT-CONTRACT.md.
Verified against s23.wad.
"""

from __future__ import annotations
import struct
import hashlib
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class WadParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 12:
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                status=OutputStatus.FAILED,
                damages=[DamageItem(kind=DamageKind.TRUNCATED, offset=0, detail="Header truncated", lossy=True)],
            )

        magic = data[:4]
        if magic not in (b"PWAD", b"IWAD"):
            return FileRecoveryResult(
                filename=filename,
                format_name="WAD",
                status=OutputStatus.UNRECOGNIZED,
                damages=[DamageItem(kind=DamageKind.HEADER_CHECKSUM, offset=0, detail="Invalid WAD magic", lossy=True)],
            )

        num_lumps, dir_offset = struct.unpack("<II", data[4:12])
        metadata = {
            "type": magic.decode("ascii"),
            "num_lumps": num_lumps,
            "dir_offset": dir_offset,
        }

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        if dir_offset + num_lumps * 16 > len(data):
            status = OutputStatus.PARTIAL
            damages.append(
                DamageItem(
                    kind=DamageKind.TRUNCATED,
                    offset=dir_offset,
                    detail="Lump directory truncated",
                    lossy=True,
                )
            )
            # Bound num_lumps to remaining bytes
            avail_lumps = max(0, (len(data) - dir_offset) // 16)
        else:
            avail_lumps = num_lumps

        for i in range(avail_lumps):
            e_off = dir_offset + i * 16
            l_off, l_sz = struct.unpack("<II", data[e_off:e_off+8])
            l_name = data[e_off+8:e_off+16].rstrip(b"\x00").decode("ascii", errors="replace")

            if l_off + l_sz > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=l_off,
                        detail=f"Lump '{l_name}' data truncated",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                lump_bytes = data[l_off:]
            else:
                lump_bytes = data[l_off:l_off+l_sz]

            sha256 = hashlib.sha256(lump_bytes).hexdigest()
            records.append({
                "name": l_name,
                "offset": l_off,
                "size": l_sz,
                "sha256": sha256,
            })

        return FileRecoveryResult(
            filename=filename,
            format_name="WAD",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
