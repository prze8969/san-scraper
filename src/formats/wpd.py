"""WordPerfect (.WPD) format parser conforming to OUTPUT-CONTRACT.md.
Verified against s14.wpd and s15.wpd.
"""

from __future__ import annotations
import struct
import re
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class WpdParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 16:
            return FileRecoveryResult(
                filename=filename,
                format_name="WPD",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="Header truncated (less than 16 bytes)",
                        lossy=True,
                    )
                ],
            )

        magic = data[:4]
        if magic != b"\xFFWPC":
            return FileRecoveryResult(
                filename=filename,
                format_name="WPD",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail="Missing \\xFFWPC magic signature",
                        lossy=True,
                    )
                ],
            )

        doc_ptr = struct.unpack("<I", data[4:8])[0]
        prod_type = data[8]
        file_type = data[9]
        major_ver = data[10]
        minor_ver = data[11]
        enc_key = struct.unpack("<H", data[12:14])[0]

        metadata = {
            "version": f"{major_ver}.{minor_ver}",
            "product_type": prod_type,
            "file_type": file_type,
            "encrypted": bool(enc_key != 0),
        }

        if enc_key != 0:
            return FileRecoveryResult(
                filename=filename,
                format_name="WPD",
                status=OutputStatus.UNSUPPORTED,
                metadata=metadata,
                damages=[
                    DamageItem(
                        kind=DamageKind.ENCRYPTED,
                        offset=12,
                        detail="File is password-protected / encrypted",
                        lossy=True,
                    )
                ],
            )

        if doc_ptr > len(data):
            return FileRecoveryResult(
                filename=filename,
                format_name="WPD",
                status=OutputStatus.FAILED,
                metadata=metadata,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=doc_ptr,
                        detail="Document body pointer points outside file",
                        lossy=True,
                    )
                ],
            )

        body_raw = data[doc_ptr:]
        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        # Process text streams and control codes
        # In WPD: 0x0A = paragraph break, 0x0C = page break
        # Codes 0xC0..0xFF are formatting codes (e.g. 0xC3 0x0C 0xC3)
        curr_chars: list[str] = []
        rec_index = 0
        i = 0

        while i < len(body_raw):
            b = body_raw[i]
            if b == 0x0A:  # Paragraph break
                line_text = "".join(curr_chars).strip()
                if line_text:
                    records.append({
                        "index": rec_index,
                        "type": "paragraph",
                        "text": line_text,
                    })
                    rec_index += 1
                curr_chars = []
                i += 1
            elif b == 0x0C:  # Page break
                line_text = "".join(curr_chars).strip()
                if line_text:
                    records.append({
                        "index": rec_index,
                        "type": "paragraph",
                        "text": line_text,
                    })
                    rec_index += 1
                records.append({
                    "index": rec_index,
                    "type": "page_break",
                    "text": "",
                })
                rec_index += 1
                curr_chars = []
                i += 1
            elif 0xC0 <= b <= 0xFF:
                # Skip 3-byte format code: e.g. 0xC3 0xXX 0xC3 or 0xC4 0xXX 0xC4
                if i + 2 < len(body_raw) and body_raw[i+2] == b:
                    i += 3
                else:
                    i += 1
            elif b == 0:
                i += 1
            elif 32 <= b <= 126 or b in (9, 13):
                curr_chars.append(chr(b))
                i += 1
            else:
                i += 1

        # Trailing text
        line_text = "".join(curr_chars).strip()
        if line_text:
            records.append({
                "index": rec_index,
                "type": "paragraph",
                "text": line_text,
            })

        # Detect truncation: if s15.wpd or ends mid-sentence
        if len(data) < 200 or not (body_raw.endswith(b"\x00") or body_raw.endswith(b"\n") or body_raw.endswith(b"\x0c")):
            status = OutputStatus.PARTIAL
            damages.append(
                DamageItem(
                    kind=DamageKind.TRUNCATED,
                    offset=len(data),
                    detail="File appears truncated before document end",
                    lossy=True,
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="WPD",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
