"""Xerox Alto Bravo format parser conforming to OUTPUT-CONTRACT.md.
Verified against s16.bravo and s17.bravo.
"""

from __future__ import annotations
import struct
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class BravoParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) == 0:
            return FileRecoveryResult(
                filename=filename,
                format_name="BRAVO",
                status=OutputStatus.FAILED,
                damages=[DamageItem(kind=DamageKind.TRUNCATED, offset=0, detail="Empty Bravo file", lossy=True)],
            )

        # Check for 0x1A (Ctrl+Z) trailer separator or carriage returns
        p_1a = data.find(b"\x1a")
        text_bytes = data[:p_1a] if p_1a != -1 else data

        # Split into CR-terminated paragraphs
        raw_paras = text_bytes.split(b"\r")
        records: list[dict[str, Any]] = []
        rec_index = 0

        for p in raw_paras:
            text = p.decode("ascii", errors="replace").strip()
            if text:
                records.append({
                    "index": rec_index,
                    "text": text,
                })
                rec_index += 1

        format_runs: list[dict[str, Any]] = []
        if p_1a != -1 and p_1a + 1 < len(data):
            trailer = data[p_1a+1:]
            # Parse format runs if present (each 6-8 bytes)
            t_idx = 0
            while t_idx + 6 <= len(trailer):
                start, length, look_code = struct.unpack("<HHH", trailer[t_idx:t_idx+6])
                looks = []
                if look_code & 0x01:
                    looks.append("bold")
                if look_code & 0x02:
                    looks.append("italic")
                if look_code & 0x04:
                    looks.append("underline")
                format_runs.append({
                    "start": start,
                    "length": length,
                    "looks": looks,
                    "font": (look_code >> 8) & 0xFF,
                })
                t_idx += 6

        metadata: dict[str, Any] = {
            "paragraph_count": len(records),
        }
        if format_runs:
            metadata["format_runs"] = format_runs

        status = OutputStatus.OK if records else OutputStatus.PARTIAL

        return FileRecoveryResult(
            filename=filename,
            format_name="BRAVO",
            status=status,
            metadata=metadata,
            records=records,
            damages=[],
        )
