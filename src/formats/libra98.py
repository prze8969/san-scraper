"""LIBRA-98 format parser conforming to OUTPUT-CONTRACT.md.
Verified against s01.dat and s04.dat ground truths.
"""

from __future__ import annotations
import struct
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class Libra98Parser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 16:
            return FileRecoveryResult(
                filename=filename,
                format_name="LIBRA-98",
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
        if magic != b"LB98":
            return FileRecoveryResult(
                filename=filename,
                format_name="LIBRA-98",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail=f"Invalid signature bytes: {magic.hex()}",
                        lossy=True,
                    )
                ],
            )

        version, declared_count = struct.unpack("<HH", data[4:8])
        dos_date, dos_time = struct.unpack("<HH", data[8:12])
        data_offset, branch_id = struct.unpack("<HH", data[12:16])

        year = ((dos_date >> 9) & 0x7F) + 1980
        month = (dos_date >> 5) & 0x0F
        day = dos_date & 0x1F
        hour = (dos_time >> 11) & 0x1F
        minute = (dos_time >> 5) & 0x3F
        second = (dos_time & 0x1F) * 2
        created = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}"

        metadata = {
            "version": version,
            "encoding": "cp437",
            "created": created,
            "branch_id": branch_id,
            "declared_record_count": declared_count,
            "data_offset": data_offset,
        }

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        offset = data_offset
        status = OutputStatus.OK

        if data_offset > len(data):
            damages.append(
                DamageItem(
                    kind=DamageKind.HEADER_CHECKSUM,
                    offset=12,
                    detail=f"Data offset {data_offset} exceeds file size",
                    lossy=True,
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LIBRA-98",
                status=OutputStatus.PARTIAL,
                metadata=metadata,
                records=[],
                damages=damages,
            )

        while offset < len(data):
            if data[offset:offset+4] == b"END!":
                offset += 6
                break

            if data[offset] != 0xA5:
                # Seek next sync marker or flag corrupt
                next_sync = data.find(b"\xA5", offset + 1)
                if next_sync != -1:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.UNPARSED_BYTES,
                            offset=offset,
                            detail=f"Skipping {next_sync - offset} unparsed bytes to next sync marker",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    offset = next_sync
                else:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.UNPARSED_BYTES,
                            offset=offset,
                            detail="Unparsed trailing bytes",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    break

            if offset + 2 > len(data):
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

            rec_len = data[offset+1]
            flags = data[offset+2]
            rec_end = offset + 2 + rec_len

            if rec_end > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail="File truncated within record",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            rec_data = data[offset+3:rec_end]
            if len(rec_data) < 4:
                offset = rec_end
                continue

            rec_id = struct.unpack("<I", rec_data[:4])[0]
            idx = 4
            title_len = rec_data[idx] if idx < len(rec_data) else 0
            idx += 1
            title = rec_data[idx:idx+title_len].decode("cp437", errors="replace")
            idx += title_len

            author_len = rec_data[idx] if idx < len(rec_data) else 0
            idx += 1
            author = rec_data[idx:idx+author_len].decode("cp437", errors="replace")
            idx += author_len

            year_val = 0
            if idx + 2 <= len(rec_data):
                y_raw = struct.unpack("<H", rec_data[idx:idx+2])[0]
                year_val = y_raw + 1500
                idx += 2

            price_cents = 0
            if idx + 2 <= len(rec_data):
                price_cents = struct.unpack("<H", rec_data[idx:idx+2])[0]
                idx += 2

            copies = rec_data[idx] if idx < len(rec_data) else 0
            idx += 1

            isbn = ""
            if idx + 10 <= len(rec_data):
                isbn = rec_data[idx:idx+10].decode("ascii", errors="replace")
                idx += 10

            checked_out = bool(flags & 0x01)
            deleted = bool(flags & 0x02)
            reference_only = bool(flags & 0x04)

            due_date = None
            if checked_out and idx + 2 <= len(rec_data):
                dd_raw = struct.unpack("<H", rec_data[idx:idx+2])[0]
                d_year = ((dd_raw >> 9) & 0x7F) + 1980
                d_month = (dd_raw >> 5) & 0x0F
                d_day = dd_raw & 0x1F
                due_date = f"{d_year:04d}-{d_month:02d}-{d_day:02d}"

            records.append({
                "id": rec_id,
                "title": title,
                "author": author,
                "year": year_val,
                "price_cents": price_cents,
                "copies": copies,
                "isbn": isbn,
                "checked_out": checked_out,
                "deleted": deleted,
                "reference_only": reference_only,
                "due_date": due_date,
            })
            offset = rec_end

        if len(records) < declared_count:
            status = OutputStatus.PARTIAL
            if not damages:
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail=f"Expected {declared_count} records, found {len(records)}",
                        lossy=True,
                    )
                )

        return FileRecoveryResult(
            filename=filename,
            format_name="LIBRA-98",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
