"""EBCDIC-DUMP format parser conforming to OUTPUT-CONTRACT.md.
Verified against s20.000, s21.000, s22.000 ground truths.
"""

from __future__ import annotations
import struct
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

def unpack_comp3(b_seq: bytes, decimals: int = 0) -> float | int:
    hex_str = b_seq.hex()
    sign = hex_str[-1].lower()
    digits = hex_str[:-1]
    try:
        val = int(digits)
    except ValueError:
        val = 0
    if sign == "d":
        val = -val
    if decimals > 0:
        return round(val / (10 ** decimals), decimals)
    return val

class EbcdicDumpParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 33:
            return FileRecoveryResult(
                filename=filename,
                format_name="EBCDIC-DUMP",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="Header truncated (less than 33 bytes)",
                        lossy=True,
                    )
                ],
            )

        offset = 0
        hdr_rdw_len = struct.unpack(">H", data[offset:offset+2])[0]
        if hdr_rdw_len < 30 or offset + hdr_rdw_len > len(data):
            return FileRecoveryResult(
                filename=filename,
                format_name="EBCDIC-DUMP",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail="Invalid header RDW length",
                        lossy=True,
                    )
                ],
            )

        hdr_rec = data[offset+4:offset+hdr_rdw_len]
        rec_type = hdr_rec[0:1].decode("cp037", errors="replace")
        if rec_type != "H":
            return FileRecoveryResult(
                filename=filename,
                format_name="EBCDIC-DUMP",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=4,
                        detail="First record is not a header record ('H')",
                        lossy=True,
                    )
                ],
            )

        title = hdr_rec[1:16].decode("cp037", errors="replace").strip()
        run_date_raw = hdr_rec[21:29].decode("cp037", errors="replace").strip()
        run_date = (
            f"{run_date_raw[:4]}-{run_date_raw[4:6]}-{run_date_raw[6:8]}"
            if len(run_date_raw) >= 8
            else run_date_raw
        )
        offset += hdr_rdw_len

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        trailer_count = 0
        trailer_credits = 0
        status = OutputStatus.OK

        while offset < len(data):
            if offset + 4 > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail="Truncated record RDW descriptor",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            rdw_len = struct.unpack(">H", data[offset:offset+2])[0]
            if rdw_len < 4 or offset + rdw_len > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail=f"Record length {rdw_len} exceeds buffer bounds",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            rec = data[offset+4:offset+rdw_len]
            r_type = rec[0:1].decode("cp037", errors="replace")

            if r_type == "D":
                if len(rec) >= 42:
                    sid = rec[1:7].decode("cp037", errors="replace").strip()
                    name = rec[7:27].decode("cp037", errors="replace").strip()
                    dob_num = unpack_comp3(rec[27:32])
                    dob_str = str(dob_num)
                    dob = (
                        f"{dob_str[:4]}-{dob_str[4:6]}-{dob_str[6:8]}"
                        if len(dob_str) >= 8
                        else dob_str
                    )
                    gpa = unpack_comp3(rec[32:35], decimals=2)
                    credits_val = struct.unpack(">H", rec[35:37])[0]
                    st_val = rec[37:38].decode("cp037", errors="replace")
                    balance = unpack_comp3(rec[38:42], decimals=2)

                    records.append({
                        "student_id": sid,
                        "name": name,
                        "dob": dob,
                        "gpa": gpa,
                        "credits": credits_val,
                        "status": st_val,
                        "balance": balance,
                    })
                else:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.TRUNCATED,
                            offset=offset,
                            detail="Data record payload truncated",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
            elif r_type == "T":
                if len(rec) >= 10:
                    trailer_count = unpack_comp3(rec[1:5])
                    trailer_credits = unpack_comp3(rec[5:10])

            offset += rdw_len

        metadata = {
            "title": title,
            "run_date": run_date,
            "trailer_count": trailer_count,
            "trailer_credits_total": trailer_credits,
        }

        return FileRecoveryResult(
            filename=filename,
            format_name="EBCDIC-DUMP",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
