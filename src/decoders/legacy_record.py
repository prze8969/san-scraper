"""Decoder for LEGACY_DATA_RECORD structured container streams.
Supports formats: XBM, BIN, SAV, DBF, PCX, CAL, DCX, PBM, TGA, CHK, ARJ, DIF, DMP, IFF, MAC, PXR, WPG, ZOO, etc.
"""

from __future__ import annotations
import hashlib
from typing import Any
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult, OutputStatus

class LegacyRecordDecoder:
    """Decodes line-structured legacy record containers with FORMAT and PROFILE headers."""

    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        data = cursor.data
        text = data.decode("latin1", errors="replace")
        lines = text.split("\n")

        header_rec = lines[0].strip() if len(lines) > 0 else ""
        fmt_line = lines[1].strip() if len(lines) > 1 else ""
        profile_line = lines[2].strip() if len(lines) > 2 else ""

        detected_format = "UNKNOWN"
        if fmt_line.startswith("FORMAT="):
            detected_format = fmt_line.split("=", 1)[1].strip().upper()

        profile = ""
        if profile_line.startswith("PROFILE="):
            profile = profile_line.split("=", 1)[1].strip()

        payload_lines = [l.strip() for l in lines[3:] if l.strip()]
        records: list[dict[str, Any]] = []

        for idx, line in enumerate(payload_lines):
            rec = {
                "record_index": idx,
                "data": line,
                "length": len(line),
                "sha256": hashlib.sha256(line.encode("latin1")).hexdigest(),
            }
            records.append(rec)

        metadata: dict[str, Any] = {
            "record_header": header_rec,
            "format": detected_format,
            "profile": profile,
            "total_records": len(records),
            "file_size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

        return FileRecoveryResult(
            filename=filename,
            format_name=detected_format,
            status=OutputStatus.OK,
            records=records,
            damages=[],
            metadata=metadata,
            file_size=len(data),
            total_records=len(records),
        )
