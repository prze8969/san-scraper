"""LABLOG format parser conforming to OUTPUT-CONTRACT.md.
Verified against s05.dat, s06.dat, s07.dat.
"""

from __future__ import annotations
import struct
import datetime
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class LablogParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 36:
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="Header truncated (less than 36 bytes)",
                        lossy=True,
                    )
                ],
            )

        magic = data[:4]
        if magic != b"LLOG":
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
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

        version = data[4]
        num_channels = data[5]
        interval_raw = struct.unpack("<H", data[6:8])[0]
        sample_interval_ms = interval_raw * 10

        inst_name = data[8:24].rstrip(b"\x00").decode("ascii", errors="replace")
        start_ts_raw = struct.unpack("<I", data[24:28])[0]
        
        # start_time_utc: seconds since 1990-01-01 00:00:00 UTC (unix epoch 631152000)
        utc_epoch_1990 = 631152000
        actual_unix_ts = utc_epoch_1990 + start_ts_raw
        dt = datetime.datetime.fromtimestamp(actual_unix_ts, tz=datetime.timezone.utc)
        start_time_utc = dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        declared_blocks = struct.unpack("<H", data[28:30])[0]

        ch_offset = 36
        channels: list[dict[str, Any]] = []
        ch_calib: list[tuple[float, float]] = []

        if ch_offset + num_channels * 12 > len(data):
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
                status=OutputStatus.PARTIAL,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=ch_offset,
                        detail="Channels descriptor truncated",
                        lossy=True,
                    )
                ],
            )

        for i in range(num_channels):
            unit_raw = data[ch_offset:ch_offset+4].rstrip(b"\x00").decode("ascii", errors="replace")
            slope, = struct.unpack("<f", data[ch_offset+4:ch_offset+8])
            intercept, = struct.unpack("<f", data[ch_offset+8:ch_offset+12])
            channels.append({"index": i, "unit": unit_raw})
            ch_calib.append((slope, intercept))
            ch_offset += 12

        # 2-byte header CRC16 follows channel definitions
        offset = ch_offset + 2

        events: list[dict[str, Any]] = []
        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        while offset < len(data):
            if data[offset] != 0xB1:
                next_b1 = data.find(b"\xB1", offset + 1)
                if next_b1 != -1:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.UNPARSED_BYTES,
                            offset=offset,
                            detail=f"Desynchronized stream: skipped {next_b1 - offset} bytes",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    offset = next_b1
                else:
                    damages.append(
                        DamageItem(
                            kind=DamageKind.UNPARSED_BYTES,
                            offset=offset,
                            detail="Trailing bytes after last block",
                            lossy=True,
                        )
                    )
                    status = OutputStatus.PARTIAL
                    break

            if offset + 4 > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail="Truncated block header",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            b_type = data[offset+1]
            b_len = struct.unpack("<H", data[offset+2:offset+4])[0]
            block_end = offset + 4 + b_len + 2  # +2 for CRC16

            if block_end > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=offset,
                        detail="Truncated block payload",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                break

            if b_type == 1:  # DATA
                start_sample = struct.unpack("<H", data[offset+4:offset+6])[0]
                count = data[offset+6]
                raw_idx = offset + 7
                for s_idx in range(count):
                    curr_sample = start_sample + s_idx
                    curr_time_ms = curr_sample * sample_interval_ms
                    vals: list[float | None] = []
                    for c in range(num_channels):
                        if raw_idx + 2 <= len(data):
                            raw_v = struct.unpack("<h", data[raw_idx:raw_idx+2])[0]
                            raw_idx += 2
                            if raw_v == -32768 or raw_v == 32767:
                                vals.append(None)
                            else:
                                slp, inter = ch_calib[c]
                                vals.append(round(raw_v * slp + inter, 4))
                        else:
                            vals.append(None)
                    records.append({
                        "sample": curr_sample,
                        "time_ms": curr_time_ms,
                        "values": vals,
                    })
            elif b_type == 2:  # EVENT
                ev_sample = struct.unpack("<H", data[offset+4:offset+6])[0]
                ev_sev = data[offset+6]
                ev_msg_len = data[offset+7]
                ev_msg = data[offset+8:offset+8+ev_msg_len].decode("ascii", errors="replace")
                events.append({
                    "sample": ev_sample,
                    "severity": ev_sev,
                    "message": ev_msg,
                })

            offset = block_end

        metadata = {
            "version": version,
            "instrument": inst_name,
            "sample_interval_ms": sample_interval_ms,
            "channels": channels,
            "start_time_utc": start_time_utc,
            "declared_block_count": declared_blocks,
            "events": events,
        }

        return FileRecoveryResult(
            filename=filename,
            format_name="LABLOG",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
