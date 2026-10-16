"""Lotus 1-2-3 (.WKS) format parser conforming to OUTPUT-CONTRACT.md.
Verified against s11.wks ground truth.
"""

from __future__ import annotations
import struct
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class WksParser(BaseParser):
    ALIGNMENT_MAP = {
        "'": "left",
        '"': "right",
        "^": "center",
        "\\": "repeat",
    }

    def _col_to_letter(self, col: int) -> str:
        if col < 26:
            return chr(ord("A") + col)
        return chr(ord("A") + (col // 26) - 1) + chr(ord("A") + (col % 26))

    def _format_cell(self, col: int, row: int) -> str:
        return f"{self._col_to_letter(col)}{row + 1}"

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 6:
            return FileRecoveryResult(
                filename=filename,
                format_name="WKS",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="File smaller than minimum BOF record",
                        lossy=True,
                    )
                ],
            )

        # First record must be BOF (opcode 0x0000, length 2)
        opcode, length = struct.unpack("<HH", data[:4])
        if opcode != 0x0000 or length != 2:
            return FileRecoveryResult(
                filename=filename,
                format_name="WKS",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail="Missing BOF record (0x0000)",
                        lossy=True,
                    )
                ],
            )

        version_word = struct.unpack("<H", data[4:6])[0]
        version_code = f"0x{version_word:04x}"

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        column_widths: dict[str, int] = {}
        declared_range = None
        status = OutputStatus.OK

        offset = 6
        saw_eof = False

        while offset < len(data):
            if offset + 4 > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail="Truncated record header",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            op, pay_len = struct.unpack("<HH", data[offset:offset+4])
            rec_end = offset + 4 + pay_len

            if rec_end > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail=f"Record opcode 0x{op:04x} truncated",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            payload = data[offset+4:rec_end]

            if op == 0x0001:  # EOF
                saw_eof = True
                offset = rec_end
                break
            elif op == 0x0006:  # RANGE
                if len(payload) >= 8:
                    sc, sr, ec, er = struct.unpack("<HHHH", payload[:8])
                    declared_range = f"{self._format_cell(sc, sr)}:{self._format_cell(ec, er)}"
            elif op == 0x0008:  # COLW (column width)
                if len(payload) >= 3:
                    col_idx, width = struct.unpack("<HB", payload[:3])
                    column_widths[self._col_to_letter(col_idx)] = width
            elif op == 0x000C:  # BLANK
                if len(payload) >= 5:
                    fmt_b, col, row = struct.unpack("<BHH", payload[:5])
                    records.append({
                        "cell": self._format_cell(col, row),
                        "col": col,
                        "row": row,
                        "type": "blank",
                        "value": None,
                    })
            elif op == 0x000D:  # INTEGER
                if len(payload) >= 7:
                    fmt_b, col, row, val = struct.unpack("<BHHh", payload[:7])
                    records.append({
                        "cell": self._format_cell(col, row),
                        "col": col,
                        "row": row,
                        "type": "integer",
                        "value": val,
                    })
            elif op == 0x000E:  # NUMBER
                if len(payload) >= 13:
                    fmt_b, col, row = struct.unpack("<BHH", payload[:5])
                    val, = struct.unpack("<d", payload[5:13])
                    records.append({
                        "cell": self._format_cell(col, row),
                        "col": col,
                        "row": row,
                        "type": "number",
                        "value": val,
                    })
            elif op == 0x000F:  # LABEL
                if len(payload) >= 6:
                    fmt_b, col, row = struct.unpack("<BHH", payload[:5])
                    align_char = chr(payload[5]) if chr(payload[5]) in self.ALIGNMENT_MAP else "'"
                    text = payload[6:].rstrip(b"\x00").decode("cp437", errors="replace")
                    records.append({
                        "cell": self._format_cell(col, row),
                        "col": col,
                        "row": row,
                        "type": "label",
                        "value": text,
                        "alignment": self.ALIGNMENT_MAP.get(align_char, "left"),
                    })
            elif op == 0x0010:  # FORMULA
                if len(payload) >= 13:
                    fmt_b, col, row = struct.unpack("<BHH", payload[:5])
                    val, = struct.unpack("<d", payload[5:13])
                    # Bytecode starts at offset 15 (skipping 2-byte bytecode length at 13:15)
                    raw_formula = payload[15:].hex() if len(payload) >= 15 else payload[13:].hex()
                    records.append({
                        "cell": self._format_cell(col, row),
                        "col": col,
                        "row": row,
                        "type": "formula",
                        "cached_value": val,
                        "formula_raw_hex": raw_formula,
                    })

            offset = rec_end

        if not saw_eof:
            status = OutputStatus.PARTIAL
            damages.append(
                DamageItem(
                    kind=DamageKind.TRUNCATED,
                    offset=offset,
                    detail="Missing EOF record (0x0001)",
                    lossy=True,
                )
            )

        metadata: dict[str, Any] = {
            "version_code": version_code,
        }
        if declared_range:
            metadata["declared_range"] = declared_range
        if column_widths:
            metadata["column_widths"] = column_widths

        return FileRecoveryResult(
            filename=filename,
            format_name="WKS",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
