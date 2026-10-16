"""Extraction helper to write recovered container files to <output_dir>/<name>.extracted/."""

from __future__ import annotations
import os
import re
from pathlib import Path
from src.models import FileRecoveryResult

def extract_container_files(
    result: FileRecoveryResult,
    raw_data: bytes,
    output_dir: Path | str | None,
) -> None:
    """Extracts intact records from container formats (e.g. PAK, WAD, ZIP) to <output_dir>/<name>.extracted/."""
    if not output_dir:
        return

    out_base = Path(output_dir) / f"{Path(result.filename).name}.extracted"

    for rec in result.recovered_records:
        if rec.status.value in ("unrecoverable", "corrupted"):
            continue

        name = rec.fields.get("name")
        if not name:
            continue

        # Sanitize relative subpath
        clean_name = name.replace("\\", "/").lstrip("/")
        # Remove any path traversal or invalid components
        parts = [p for p in clean_name.split("/") if p and p != ".." and p != "."]
        if not parts:
            parts = [f"entry_{rec.record_id}"]
        safe_rel_path = Path(*parts)

        target_file = (out_base / safe_rel_path).resolve()
        resolved_base = out_base.resolve()

        # Strict containment check
        try:
            target_file.relative_to(resolved_base)
        except ValueError:
            continue

        # Slice payload
        start, end = rec.byte_range
        if start < 0 or end > len(raw_data) or start > end:
            continue

        # If entry was decompressed (e.g. ZIP deflate), write decompressed payload if present
        payload = rec.fields.get("decompressed_data")
        if payload is None:
            payload = raw_data[start:end]

        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_bytes(payload)
            rec.fields["extracted_path"] = str(target_file)
        except Exception:
            pass
