"""EBCDIC-DUMP format parser conforming to OUTPUT-CONTRACT.md.
Supports both unblocked record format (RDW-only, e.g. s20.000, s22.000)
and IBM variable-blocked record format (BDW + RDW, e.g. s21.000).
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

        # Detect whether stream uses Variable Blocked (BDW + RDW) or Unblocked (RDW only)
        # In IBM format, BDW has 2 bytes length + 2 bytes 0x0000.
        # Check if byte 4 is start of an RDW that contains Header 'H' (0xC8 in CP037) at offset 8:
        is_blocked = False
        if len(data) >= 9 and data[2:4] == b"\x00\x00" and data[6:8] == b"\x00\x00":
            # Test if offset 8 is 'H' (0xC8)
            if data[8:9] == b"\xC8":
                is_blocked = True

        title = ""
        run_date = ""
        trailer_count = 0
        trailer_credits = 0
        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        def process_record(rec: bytes, rec_offset: int) -> None:
            nonlocal title, run_date, trailer_count, trailer_credits, status
            if not rec:
                return
            r_type = rec[0:1].decode("cp037", errors="replace")
            if r_type == "H":
                title = rec[1:16].decode("cp037", errors="replace").strip()
                run_date_raw = rec[21:29].decode("cp037", errors="replace").strip()
                run_date = (
                    f"{run_date_raw[:4]}-{run_date_raw[4:6]}-{run_date_raw[6:8]}"
                    if len(run_date_raw) >= 8
                    else run_date_raw
                )
            elif r_type == "D":
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
                            offset=rec_offset,
                            detail="Data record payload truncated",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
            elif r_type == "T":
                if len(rec) >= 10:
                    trailer_count = unpack_comp3(rec[1:5])
                    trailer_credits = unpack_comp3(rec[5:10])

        if is_blocked:
            pos = 0
            while pos < len(data):
                if pos + 4 > len(data):
                    damages.append(
                        DamageItem(
                            kind=DamageKind.TRUNCATED,
                            offset=pos,
                            detail="Truncated Block Descriptor Word (BDW)",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    break
                bdw_len = struct.unpack(">H", data[pos:pos+2])[0]
                if bdw_len < 4:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.BAD_LENGTH,
                            offset=pos,
                            detail=f"Invalid BDW length {bdw_len}",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    break
                blk_end = min(len(data), pos + bdw_len)
                r_pos = pos + 4
                while r_pos < blk_end:
                    if r_pos + 4 > len(data):
                        damages.append(
                            DamageItem(
                                kind=DamageKind.TRUNCATED,
                                offset=r_pos,
                                detail="Truncated RDW descriptor",
                                lossy=True,
                            )
                        )
                        status = OutputStatus.PARTIAL
                        break
                    rdw_len = struct.unpack(">H", data[r_pos:r_pos+2])[0]
                    if rdw_len < 4 or r_pos + rdw_len > blk_end:
                        damages.append(
                            DamageItem(
                                kind=DamageKind.TRUNCATED,
                                offset=r_pos,
                                detail="RDW length exceeds block boundary",
                                lossy=True,
                            )
                        )
                        status = OutputStatus.PARTIAL
                        break
                    rec_payload = data[r_pos+4:r_pos+rdw_len]
                    process_record(rec_payload, r_pos)
                    r_pos += rdw_len
                pos = pos + bdw_len
        else:
            # Unblocked stream
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

            process_record(hdr_rec, offset)
            offset += hdr_rdw_len

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
                process_record(rec, offset)
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
