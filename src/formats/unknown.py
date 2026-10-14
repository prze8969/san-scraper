"""Unknown and Empty file handlers with defensive damage logging."""

from __future__ import annotations
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, DamageBlock, DamageType

class UnknownParser(BaseParser):
    """Handles unsupported or unrecognized files gracefully without crashing."""

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        size = reader.size
        damages = []
        if size == 0:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=0,
                    damage_type=DamageType.TRUNCATION,
                    description="File is empty (0 bytes)",
                )
            )
            fmt = "EMPTY"
            meta = {"status": "skipped", "reason": "empty_file"}
        else:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=min(16, size),
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Unrecognized magic bytes: {reader.peek_bytes(8).hex()}",
                )
            )
            fmt = "UNKNOWN"

            preview_bytes = reader.peek_bytes(min(64, size))
            ascii_text = preview_bytes.decode("latin-1", errors="replace").replace("\r", " ").replace("\n", " ")
            meta = {
                "status": "skipped",
                "reason": "unrecognized_format",
                "preview_hex": preview_bytes.hex(),
                "preview_text": ascii_text,
            }

        return FileRecoveryResult(
            filename=filename,
            format_name=fmt,
            file_size=size,
            is_valid_header=False,
            total_records=0,
            recovered_records=[],
            damages=damages,
            metadata=meta,
        )
