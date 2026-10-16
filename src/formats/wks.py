"""Parser for Lotus 1-2-3 Release 1A .WKS spreadsheet format."""

from __future__ import annotations
import struct
from datetime import date, timedelta
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

LOTUS_SPECIAL_FORMATS: dict[int, str] = {
    0: "",
    1: "General",
    2: "d-mmm-yy",
    3: "d-mmm",
    4: "mmm yy",
    6: ";;;",
    7: "h:mm:ss AM/PM",
    8: "h:mm",
    9: "m/d/yy",
    10: "d/m/yy",
}

LABEL_ALIGNMENT_MAP: dict[int, str] = {
    ord("'"): "left",
    ord('"'): "right",
    ord("^"): "center",
    ord("\\"): "repeat",
}


def col_to_letter(col: int) -> str:
    """Converts a 0-based column index to spreadsheet letter(s) (e.g. 0 -> 'A', 27 -> 'AB')."""
    res = ""
    col += 1
    while col > 0:
        col, rem = divmod(col - 1, 26)
        res = chr(ord("A") + rem) + res
    return res


def cell_address(col: int, row: int) -> str:
    """Converts 0-based col and row into standard cell notation (e.g. (0, 0) -> 'A1')."""
    return f"{col_to_letter(col)}{row + 1}"


def decode_format_byte(fmt_byte: int) -> tuple[str | None, bool]:
    """
    Decodes the Lotus 1-2-3 cell format byte.
    Format byte layout:
      Bit 7: Protection flag (1 = protected)
      Bits 4..6: Format type (0 = fixed, 1 = scientific, 2 = currency, 3 = percent, 4 = comma, 7 = special)
      Bits 0..3: Decimal places / subtype (0..15)
      0xFF: Default / unformatted
    Returns (number_format_string, is_date_format).
    """
    if fmt_byte == 0xFF:
        return None, False

    fmt_type = (fmt_byte >> 4) & 0x07
    prec = fmt_byte & 0x0F

    if fmt_type == 0:  # Fixed
        zeros = "0" * prec
        return (f"0.{zeros}" if prec > 0 else "0"), False
    elif fmt_type == 1:  # Scientific
        zeros = "0" * prec
        return (f"0.{zeros}E+00" if prec > 0 else "0E+00"), False
    elif fmt_type == 2:  # Currency
        zeros = "0" * prec
        return (f"$#,##0.{zeros}" if prec > 0 else "$#,##0"), False
    elif fmt_type == 3:  # Percent
        zeros = "0" * prec
        return (f"0.{zeros}%" if prec > 0 else "0%"), False
    elif fmt_type == 4:  # Comma
        zeros = "0" * prec
        return (f"#,##0.{zeros}" if prec > 0 else "#,##0"), False
    elif fmt_type == 7:  # Special
        special = LOTUS_SPECIAL_FORMATS.get(prec, "")
        is_date = prec in (2, 3, 4, 9, 10)
        return (special if special else None), is_date

    return None, False


def serial_to_iso_date(serial: float | int) -> str | None:
    """
    Converts a Lotus 1-2-3 serial date number to ISO YYYY-MM-DD.
    Lotus 1-2-3 epoch is 1899-12-31 with the famous 1900 leap year bug:
      Serial 1 = 1900-01-01
      Serial 59 = 1900-02-28
      Serial 60 = 1900-02-29 (phantom leap day)
      Serial 61 = 1900-03-01
    """
    try:
        val = int(serial)
        if val <= 0:
            return None
        if val < 60:
            d = date(1899, 12, 31) + timedelta(days=val)
        elif val == 60:
            return "1900-02-28"  # Approximate phantom leap day gracefully
        else:
            d = date(1899, 12, 30) + timedelta(days=val)
        return d.isoformat()
    except Exception:
        return None


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
      0x0006: RANGE (Declared range: col1, row1, col2, row2)
      0x0008: COLUMN WIDTH (col uint16, width uint8)
      0x000C: BLANK cell (format byte, uint16 col, uint16 row)
      0x000D: INTEGER cell (format byte, uint16 col, uint16 row, int16 value)
      0x000E: NUMBER cell (format byte, uint16 col, uint16 row, double 64-bit value)
      0x000F: LABEL cell (format byte, uint16 col, uint16 row, align byte, string)
      0x0010: FORMULA cell (format byte, uint16 col, uint16 row, 8B cached val, 2B bytecode len, bytecode)
    """

    OPCODE_BOF = 0x0000
    OPCODE_EOF = 0x0001
    OPCODE_RANGE = 0x0006
    OPCODE_COLWIDTH = 0x0008
    OPCODE_BLANK = 0x000C
    OPCODE_INTEGER = 0x000D
    OPCODE_NUMBER = 0x000E
    OPCODE_LABEL = 0x000F
    OPCODE_FORMULA = 0x0010

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
        declared_range = None
        column_widths: dict[str, int] = {}

        if file_size < 6:
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

            # Metadata opcodes
            if opcode == self.OPCODE_RANGE and payload_len >= 8:
                col1, row1, col2, row2 = struct.unpack("<HHHH", payload_bytes[:8])
                declared_range = f"{cell_address(col1, row1)}:{cell_address(col2, row2)}"
                rec_idx += 1
                continue

            if opcode == self.OPCODE_COLWIDTH and payload_len >= 3:
                col, width = struct.unpack("<HB", payload_bytes[:3])
                column_widths[col_to_letter(col)] = width
                rec_idx += 1
                continue

            # Cell records
            cell_fields: dict[str, Any] = {}
            errors: list[str] = []

            # 1. BLANK cell
            if opcode == self.OPCODE_BLANK and payload_len == 5:
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                cell_fields = {
                    "cell": cell_address(col, row),
                    "col": col,
                    "row": row,
                    "type": "blank",
                    "value": None,
                    "record_type": "BLANK",
                }
            # 2. INTEGER cell
            elif (
                (opcode == self.OPCODE_INTEGER or (opcode == self.ALT_OPCODE_INTEGER and payload_len == 7))
                and payload_len >= 7
            ):
                fmt_byte, col, row, val = struct.unpack("<BHHh", payload_bytes[:7])
                cell_fields = {
                    "cell": cell_address(col, row),
                    "col": col,
                    "row": row,
                    "type": "integer",
                    "value": val,
                    "record_type": "INTEGER",
                }
            # 3. NUMBER cell
            elif (opcode == self.OPCODE_NUMBER or opcode == self.ALT_OPCODE_NUMBER) and payload_len >= 13:
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                val = None
                if payload_len >= 15:
                    try:
                        mantissa, exp_sign = struct.unpack("<QH", payload_bytes[5:15])
                        sign = -1.0 if (exp_sign & 0x8000) else 1.0
                        exp = (exp_sign & 0x7FFF) - 16383
                        if exp == 16384:
                            val = float("nan") if mantissa != 0 else (sign * float("inf"))
                        elif exp == -16383:
                            val = 0.0
                        else:
                            val = sign * (mantissa / (2**63)) * (2.0**exp)
                    except Exception:
                        val = struct.unpack("<d", payload_bytes[5:13])[0]
                else:
                    val = struct.unpack("<d", payload_bytes[5:13])[0]

                cell_fields = {
                    "cell": cell_address(col, row),
                    "col": col,
                    "row": row,
                    "type": "number",
                    "value": val,
                    "record_type": "NUMBER",
                }
                num_fmt, is_date = decode_format_byte(fmt_byte)
                if is_date:
                    iso = serial_to_iso_date(val)
                    if iso:
                        cell_fields["iso_date"] = iso

            # 4. LABEL cell
            elif (opcode == self.OPCODE_LABEL or opcode == self.ALT_OPCODE_LABEL) and payload_len >= 6:
                fmt_byte, col, row, align_byte = struct.unpack("<BHHB", payload_bytes[:6])
                align_str = LABEL_ALIGNMENT_MAP.get(align_byte, "left")
                text_raw = payload_bytes[6:].split(b"\x00", 1)[0]
                text_str = text_raw.decode("cp437", errors="replace")
                cell_fields = {
                    "cell": cell_address(col, row),
                    "col": col,
                    "row": row,
                    "type": "label",
                    "value": text_str,
                    "alignment": align_str,
                    "align_prefix": chr(align_byte) if 32 <= align_byte <= 126 else "",
                    "text": text_str,
                    "record_type": "LABEL",
                }

            # 5. FORMULA cell
            elif (opcode == self.OPCODE_FORMULA or opcode == self.ALT_OPCODE_FORMULA) and payload_len >= 5:
                fmt_byte, col, row = struct.unpack("<BHH", payload_bytes[:5])
                cached_val = None
                bc_hex = ""
                if payload_len >= 13:
                    cached_val = struct.unpack("<d", payload_bytes[5:13])[0]
                if payload_len >= 15:
                    bc_len = struct.unpack("<H", payload_bytes[13:15])[0]
                    bc_hex = payload_bytes[15 : 15 + bc_len].hex()

                cell_fields = {
                    "cell": cell_address(col, row),
                    "col": col,
                    "row": row,
                    "type": "formula",
                    "cached_value": cached_val,
                    "formula_raw_hex": bc_hex,
                    "record_type": "FORMULA",
                }
            else:
                cell_fields = {
                    "record_type": f"UNKNOWN_OPCODE_0x{opcode:04X}",
                    "raw_hex": payload_bytes[:32].hex(),
                    "opcode": opcode,
                }

            recovered_records.append(
                RecoveredRecord(
                    record_id=rec_idx,
                    status=RecordStatus.COMPLETE,
                    byte_range=(rec_start, rec_end),
                    fields=cell_fields,
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

        meta: dict[str, Any] = {
            "saw_bof": saw_bof,
            "saw_eof": saw_eof,
            "version_code": f"0x{version_code:04x}" if version_code is not None else None,
        }
        if declared_range is not None:
            meta["declared_range"] = declared_range
        if column_widths:
            meta["column_widths"] = column_widths

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
