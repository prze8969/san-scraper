"""Fallback handler for unrecognized or damaged binary streams conforming to OUTPUT-CONTRACT.md."""

from __future__ import annotations
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class UnknownParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) == 0:
            return FileRecoveryResult(
                filename=filename,
                format_name="UNKNOWN",
                status=OutputStatus.OK,
                metadata={"reason": "empty_file", "size": 0},
                records=[],
                damages=[],
            )

        preview = data[:32].hex()
        preview_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:32])

        return FileRecoveryResult(
            filename=filename,
            format_name="UNKNOWN",
            status=OutputStatus.UNRECOGNIZED,
            metadata={
                "preview_hex": preview,
                "preview_text": preview_text,
                "size": len(data),
            },
            records=[],
            damages=[
                DamageItem(
                    kind=DamageKind.UNKNOWN_RECORD,
                    offset=0,
                    detail=f"Unrecognized binary format (magic: {data[:8].hex()})",
                    lossy=True,
                )
            ],
        )
