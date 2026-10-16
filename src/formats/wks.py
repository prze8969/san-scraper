"""Parser for Lotus 1-2-3 Release 1A .WKS spreadsheet format."""

from __future__ import annotations
import struct
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class WksParser(BaseParser):
    """
    Defensive parser for Lotus 1-2-3 Release 1A (.WKS) sequential record stream.

    Sequential Record Layout:
      +0x00..+0x02: Opcode (uint16, little-endian)
      +0x02..+0x04: Length N (uint16, little-endian)
      +0x04..+0x04+N: Payload (N bytes)

    Opcodes:
      0x0000: BOF (Beginning of file, length 2, Release 1A version = 0x0404)
      0x0001: EOF (End of file, length 0)
      0x000C: INTEGER cell (format byte, uint16 col, uint16 row, int16 value)
      0x000D: NUMBER cell (format byte, uint16 col, uint16 row, double 64-bit value)
      0x000E: LABEL cell (format byte, uint16 col, uint16 row, align byte, string)
      0x000F: FORMULA cell (inert, formula tree not executed)
    """

    # Authoritative Lotus 1-2-3 Release 1A / WK1 Record Opcodes:
    # Reference: Lotus 1-2-3 File Format Specification; Gnumeric lotus.c; LibreOffice sc/source/filter/lotus
    OPCODE_BOF = 0x0000        # Beginning of file (length 2, Release 1A version = 0x0404)
    OPCODE_EOF = 0x0001        # End of file (length 0)
    OPCODE_BLANK = 0x000C      # Blank cell (4 bytes payload: format byte, col uint16, row uint16)
    OPCODE_INTEGER = 0x000D    # Integer cell (7 bytes payload: format byte, col uint16, row uint16, int16 val)
    OPCODE_NUMBER = 0x000E     # Floating-point number (13 bytes payload: format byte, col uint16, row uint16, double 64-bit val)
    OPCODE_LABEL = 0x000F      # Label/text string (min 6 bytes: format byte, col uint16, row uint16, align byte, string)
    OPCODE_FORMULA = 0x0010    # Formula cell (inert data: format byte, col uint16, row uint16, 8-byte float result, formula tree)

    # Legacy / Alternate mapping compatibility aliases:
    ALT_OPCODE_INTEGER = 0x000C
    ALT_OPCODE_NUMBER = 0x000D
    ALT_OPCODE_LABEL = 0x000E
    ALT_OPCODE_FORMULA = 0x000F

    WKS_RELEASE_1A_VERSION = 0x0404
    HEADER_SIZE = 4
    MAX_RECORD_LENGTH = 65536
    MAX_RECORDS = 50000

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False
        saw_bof = False
        saw_eof = False
        version_code = None

        if file_size < 6:  # BOF record is minimum 6 bytes (2B opcode, 2B len, 2B payload)
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum Lotus 1-2-3 BOF record ({file_size} < 6)",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="WKS",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        # Check BOF
        try:
            first_opcode = reader.read_u16_le()
            first_len = reader.read_u16_le()
            if first_opcode == self.OPCODE_BOF:
                saw_bof = True
                if first_len >= 2:
                    version_code = reader.read_u16_le()
                    reader.skip(first_len - 2)
                    if version_code == self.WKS_RELEASE_1A_VERSION:
                        is_valid_header = True
                    else:
                        damages.append(
                            DamageBlock(
                                offset=4,
                                length=2,
                                damage_type=DamageType.INVALID_HEADER,
                                description=f"Unsupported or non-Release 1A Lotus revision: 0x{version_code:04X}",
                            )
                        )
                        is_valid_header = True  # Proceed with best-effort parsing
                else:
                    reader.skip(first_len)
            else:
                reader.seek(0)
                damages.append(
                    DamageBlock(
                        offset=0,
                        length=4,
                        damage_type=DamageType.INVALID_HEADER,
                        description=f"Initial record is not BOF (opcode 0x{first_opcode:04X})",
                    )
                )
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.TRUNCATION,
                    description=f"Truncated header during BOF: {str(e)}",
                )
            )

        # Parse sequential records
        rec_idx = 0
        while not reader.is_eof() and rec_idx < self.MAX_RECORDS:
            rec_start = reader.position

            if reader.remaining < 4:
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=reader.remaining,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Truncated record header at offset {rec_start} ({reader.remaining} bytes left)",
                    )
                )
                break

            opcode = reader.read_u16_le()
            payload_len = reader.read_u16_le()

            if payload_len > self.MAX_RECORD_LENGTH:
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=4,
                        damage_type=DamageType.CORRUPT_RECORD,
                        description=f"Record {rec_idx} payload length {payload_len} exceeds limit",
                    )
                )
                break

            if reader.remaining < payload_len:
                damages.append(
                    DamageBlock(
                        offset=rec_start,
                        length=reader.remaining + 4,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Record {rec_idx} payload truncated (expected {payload_len}, got {reader.remaining})",
                    )
                )
                break

            payload_bytes = reader.read_bytes(payload_len)
            rec_end = reader.position

            if opcode == self.OPCODE_EOF:
                saw_eof = True
                recovered_records.append(
                    RecoveredRecord(
                        record_id=rec_idx,
                        status=RecordStatus.COMPLETE,
                        byte_range=(rec_start, rec_end),
                        fields={"record_type": "EOF", "opcode": opcode},
                    )
                )
                break

            fields: dict = {"opcode": opcode, "payload_len": payload_len}
            errors: list[str] = []

            # Decode verified cell records
            if opcode == self.OPCODE_BLANK and payload_len == 5:
                # Format (1B), Col (2B), Row (2B)
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                fields.update({
                    "record_type": "BLANK",
                    "col": col,
                    "row": row,
                    "format_byte": fmt_byte,
                })
            elif (opcode == self.OPCODE_INTEGER or (opcode == self.ALT_OPCODE_INTEGER and payload_len == 7)) and payload_len >= 7:
                # Format (1B), Col (2B), Row (2B), Value (2B int16)
                fmt_byte, col, row, val = struct.unpack("<BHHh", payload_bytes[:7])
                fields.update({
                    "record_type": "INTEGER",
                    "col": col,
                    "row": row,
                    "value": val,
                    "format_byte": fmt_byte,
                })
            elif (opcode == self.OPCODE_NUMBER or opcode == self.ALT_OPCODE_NUMBER) and payload_len >= 13:
                # Format (1B), Col (2B), Row (2B), Value (8B double or 10B 80-bit float)
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                val = None
                if payload_len >= 15:
                    # 10-byte 80-bit IEEE 754 extended precision float fallback:
                    # bytes 5..15: 80-bit float (10 bytes: 8 bytes mantissa + 2 bytes sign/exponent)
                    # We can attempt to parse it, or fall back to 8-byte double if standard
                    try:
                        mantissa, exp_sign = struct.unpack("<QH", payload_bytes[5:15])
                        sign = -1.0 if (exp_sign & 0x8000) else 1.0
                        exp = (exp_sign & 0x7FFF) - 16383
                        if exp == 16384:
                            val = float('nan') if mantissa != 0 else (sign * float('inf'))
                        elif exp == -16383:
                            val = 0.0
                        else:
                            val = sign * (mantissa / (2**63)) * (2.0 ** exp)
                    except Exception:
                        val = struct.unpack("<d", payload_bytes[5:13])[0]
                else:
                    val = struct.unpack("<d", payload_bytes[5:13])[0]

                fields.update({
                    "record_type": "NUMBER",
                    "col": col,
                    "row": row,
                    "value": val,
                    "format_byte": fmt_byte,
                })
            elif (opcode == self.OPCODE_LABEL or opcode == self.ALT_OPCODE_LABEL) and payload_len >= 6:
                # Format (1B), Col (2B), Row (2B), Align (1B), Text (null-terminated string)
                fmt_byte, col, row, align_byte = struct.unpack("<BHHB", payload_bytes[:6])
                text_raw = payload_bytes[6:].split(b"\x00", 1)[0]
                text_str = text_raw.decode("latin-1", errors="replace")
                fields.update({
                    "record_type": "LABEL",
                    "col": col,
                    "row": row,
                    "align_prefix": chr(align_byte) if 32 <= align_byte <= 126 else "",
                    "text": text_str,
                    "format_byte": fmt_byte,
                })
            elif (opcode == self.OPCODE_FORMULA or opcode == self.ALT_OPCODE_FORMULA) and payload_len >= 5:
                # Inert formula record
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                cached_val = None
                if payload_len >= 13:
                    cached_val = struct.unpack("<d", payload_bytes[5:13])[0]
                fields.update({
                    "record_type": "FORMULA",
                    "col": col,
                    "row": row,
                    "cached_value": cached_val,
                    "note": "Formula treated as inert data",
                })
            else:
                fields.update({
                    "record_type": f"UNKNOWN_OPCODE_0x{opcode:04X}",
                    "raw_hex": payload_bytes[:32].hex(),
                })

            recovered_records.append(
                RecoveredRecord(
                    record_id=rec_idx,
                    status=RecordStatus.COMPLETE,
                    byte_range=(rec_start, rec_end),
                    fields=fields,
                    errors=errors,
                )
            )
            rec_idx += 1

        if not saw_eof:
            damages.append(
                DamageBlock(
                    offset=reader.position,
                    length=reader.remaining,
                    damage_type=DamageType.TRUNCATION,
                    description="Missing terminating EOF record in Lotus 1-2-3 stream",
                )
            )

        # Build grid-style cell table for metadata
        grid: dict[str, Any] = {}
        for r in recovered_records:
            if "row" in r.fields and "col" in r.fields:
                row_idx = r.fields["row"]
                col_idx = r.fields["col"]
                cell_key = f"R{row_idx}C{col_idx}"
                cell_info: dict[str, Any] = {"type": r.fields.get("record_type")}
                if "value" in r.fields:
                    cell_info["value"] = r.fields["value"]
                elif "text" in r.fields:
                    cell_info["value"] = r.fields["text"]
                elif "cached_value" in r.fields:
                    cell_info["value"] = r.fields["cached_value"]
                grid[cell_key] = cell_info

        meta = {
            "saw_bof": saw_bof,
            "saw_eof": saw_eof,
            "version_code": f"0x{version_code:04X}" if version_code is not None else None,
        }
        if grid:
            meta["grid"] = grid

        return FileRecoveryResult(
            filename=filename,
            format_name="WKS",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=len(recovered_records),
            recovered_records=recovered_records,
            damages=damages,
            metadata=meta,
        )
