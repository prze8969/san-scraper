"""Calibrated parser for LABLOG format based on authoritative judges' samples (s05-s07).

Layout Specification (reverse-engineered from samples s05-s07 and reference output s05):

Header (32 bytes):
  0x00..0x04: Magic b'LLOG' (4 bytes)
  0x04: Version uint8 (expected 1)
  0x05: Number of channels uint8
  0x06..0x08: Sample interval raw units uint16 LE (sample_interval_ms = units * 10)
  0x08..0x24: Instrument name (16 bytes, ASCII null-padded)
  0x24..0x28: Start timestamp in seconds since 1990-01-01 00:00:00 UTC uint32 LE
  0x28..0x2A: Declared block count uint16 LE (total blocks including channel block)
  0x2A..0x2C: Reserved (2 bytes zeros)
  0x2C..0x2E: Reserved (2 bytes zeros)
  0x2E..0x30: Reserved (2 bytes zeros)
  0x30..0x32: Header CRC16-CCITT (init 0xFFFF) over bytes 0x00..0x30

Channel Definition Block (follows header):
  +0x00: Sync tag 0xB1 (1 byte)
  +0x01: Block type 0x03 (channel config)
  +0x02..+0x04: Payload length uint16 LE (num_channels * 12)
  +0x04..: Per channel (12 bytes each):
    +0x00..+0x04: Unit string (4 bytes ASCII, null-padded)
    +0x04..+0x08: Scale factor float32 LE
    +0x08..+0x0C: Offset value float32 LE
  Followed by 2-byte CRC16-CCITT over type + len + payload

Blocks (sequential):
  +0x00: Sync tag 0xB1 (1 byte)
  +0x01: Block type uint8 (1 = data block, 2 = event block)
  +0x02..+0x04: Payload length uint16 LE
  +0x04..+0x04+len: Payload
  Followed by 2-byte CRC16-CCITT over type + len + payload

Type 1 (Data Block):
  +0x00..+0x02: Start sample index uint16 LE
  +0x02: Sample count uint8
  +0x03..: Samples (sample_count * num_channels * int16 LE readings)
    calibrated_val = raw_int16 * scale + offset

Type 2 (Event Block):
  +0x00..+0x02: Sample index uint16 LE
  +0x02: Severity uint8
  +0x03: Message length uint8
  +0x04..: Message ASCII string
"""

from __future__ import annotations
import struct
import datetime
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)


def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    crc = init
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


class LablogParser(BaseParser):
    """Calibrated defensive parser for LABLOG files."""

    MAGIC = b"LLOG"
    SYNC_BYTE = 0xB1
    HEADER_SIZE = 32

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        if file_size < self.HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than LABLOG header ({file_size} < {self.HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={},
            )

        data = reader.peek_bytes(file_size, offset=0)
        magic = data[:4]
        if magic != self.MAGIC:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=4,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Invalid LABLOG magic {magic}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="LABLOG",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={},
            )

        # Parse header
        ver = data[4]
        num_ch = data[5]
        interval_units = struct.unpack("<H", data[6:8])[0]
        sample_interval_ms = interval_units * 10
        instrument = data[8:24].rstrip(b"\x00").decode("ascii", errors="replace")
        start_sec, decl_blocks = struct.unpack("<IH", data[24:30])

        stored_hdr_csum = struct.unpack("<H", data[30:32])[0]
        calc_hdr_csum = crc16_ccitt(data[:30])
        if stored_hdr_csum == calc_hdr_csum:
            is_valid_header = True
        else:
            is_valid_header = True
            damages.append(
                DamageBlock(
                    offset=30,
                    length=2,
                    damage_type=DamageType.CHECKSUM_MISMATCH,
                    description=f"Header CRC16 mismatch: declared 0x{stored_hdr_csum:04x}, computed 0x{calc_hdr_csum:04x}",
                )
            )

        epoch_1990 = datetime.datetime(1990, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        start_time_dt = epoch_1990 + datetime.timedelta(seconds=start_sec)
        start_time_utc = start_time_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Parse Channel Block at offset 32
        pos = 32
        channels: list[dict] = []
        channel_calibrations: list[tuple[float, float]] = []

        if pos + 4 <= file_size:
            ch_tag = data[pos]
            ch_type = data[pos + 1]
            ch_len = struct.unpack("<H", data[pos + 2 : pos + 4])[0]
            if ch_tag == self.SYNC_BYTE and ch_type == 3:
                ch_end = pos + 4 + ch_len + 2
                if ch_end <= file_size:
                    stored_ch_csum = struct.unpack("<H", data[pos + 4 + ch_len : ch_end])[0]
                    calc_ch_csum = crc16_ccitt(data[pos + 1 : pos + 4 + ch_len])
                    if stored_ch_csum != calc_ch_csum:
                        damages.append(
                            DamageBlock(
                                offset=pos + 4 + ch_len,
                                length=2,
                                damage_type=DamageType.CHECKSUM_MISMATCH,
                                description="Channel block CRC16 mismatch",
                            )
                        )
                    ch_payload = data[pos + 4 : pos + 4 + ch_len]
                    for ch_i in range(num_ch):
                        c_off = ch_i * 12
                        if c_off + 12 <= len(ch_payload):
                            unit_str = ch_payload[c_off : c_off + 4].rstrip(b"\x00").decode("ascii", errors="replace")
                            scale, c_offset = struct.unpack("<ff", ch_payload[c_off + 4 : c_off + 12])
                            channels.append({"index": ch_i, "unit": unit_str})
                            channel_calibrations.append((scale, c_offset))
                    pos = ch_end
                else:
                    damages.append(
                        DamageBlock(
                            offset=pos,
                            length=file_size - pos,
                            damage_type=DamageType.TRUNCATION,
                            description="Channel block truncated",
                        )
                    )
                    pos = file_size

        # Parse sequential blocks
        events: list[dict] = []
        total_blocks_found = 1 if channels else 0  # channel config is 1 block
        sample_dict: dict[int, list[float]] = {}
        sample_statuses: dict[int, RecordStatus] = {}

        while pos < file_size:
            if pos + 4 > file_size:
                damages.append(
                    DamageBlock(
                        offset=pos,
                        length=file_size - pos,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Block header truncated at {pos}",
                    )
                )
                break

            tag = data[pos]
            if tag != self.SYNC_BYTE:
                damages.append(
                    DamageBlock(
                        offset=pos,
                        length=file_size - pos,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Expected block sync 0xB1 at {pos}, got 0x{tag:02x}",
                    )
                )
                break

            btype = data[pos + 1]
            blen = struct.unpack("<H", data[pos + 2 : pos + 4])[0]
            b_end = pos + 4 + blen + 2

            if b_end > file_size:
                damages.append(
                    DamageBlock(
                        offset=pos,
                        length=file_size - pos,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Block declared len {blen} exceeds file bounds ({file_size - pos - 4} left)",
                    )
                )
                break

            stored_b_csum = struct.unpack("<H", data[pos + 4 + blen : b_end])[0]
            calc_b_csum = crc16_ccitt(data[pos + 1 : pos + 4 + blen])
            csum_ok = (stored_b_csum == calc_b_csum)
            if not csum_ok:
                damages.append(
                    DamageBlock(
                        offset=pos + 4 + blen,
                        length=2,
                        damage_type=DamageType.CHECKSUM_MISMATCH,
                        description=f"Block at {pos} CRC16 mismatch: declared 0x{stored_b_csum:04x}, computed 0x{calc_b_csum:04x}",
                    )
                )

            b_payload = data[pos + 4 : pos + 4 + blen]

            if btype == 1:  # Data block
                if len(b_payload) >= 3:
                    start_s, s_cnt = struct.unpack("<HB", b_payload[:3])
                    readings_bytes = b_payload[3:]
                    readings_per_s = num_ch * 2
                    for s_i in range(s_cnt):
                        s_idx = start_s + s_i
                        r_slice = readings_bytes[s_i * readings_per_s : (s_i + 1) * readings_per_s]
                        if len(r_slice) == readings_per_s:
                            s_vals = []
                            for ch_i in range(num_ch):
                                raw_val = struct.unpack("<h", r_slice[ch_i * 2 : (ch_i + 1) * 2])[0]
                                if ch_i < len(channel_calibrations):
                                    scale, c_off = channel_calibrations[ch_i]
                                    calibrated = round(raw_val * scale + c_off, 4)
                                    s_vals.append(calibrated)
                                else:
                                    s_vals.append(float(raw_val))
                            sample_dict[s_idx] = s_vals
                            sample_statuses[s_idx] = RecordStatus.COMPLETE if csum_ok else RecordStatus.CORRUPTED
            elif btype == 2:  # Event block
                if len(b_payload) >= 4:
                    e_samp, e_sev, e_mlen = struct.unpack("<HBB", b_payload[:4])
                    e_msg = b_payload[4 : 4 + e_mlen].decode("ascii", errors="replace")
                    events.append({
                        "sample": e_samp,
                        "severity": e_sev,
                        "message": e_msg,
                    })

            total_blocks_found += 1
            pos = b_end

        # Check block count mismatch
        if decl_blocks > 0 and total_blocks_found < decl_blocks:
            damages.append(
                DamageBlock(
                    offset=file_size,
                    length=0,
                    damage_type=DamageType.COUNT_MISMATCH,
                    description=f"Declared block count {decl_blocks} exceeds found blocks {total_blocks_found}",
                )
            )

        # Assemble records sorted by sample index
        for s_idx in sorted(sample_dict.keys()):
            vals = sample_dict[s_idx]
            rec_st = sample_statuses.get(s_idx, RecordStatus.COMPLETE)
            errors = ["Block CRC mismatch"] if rec_st == RecordStatus.CORRUPTED else []
            recovered_records.append(
                RecoveredRecord(
                    record_id=s_idx,
                    status=rec_st,
                    byte_range=(0, 0),
                    fields={
                        "sample": s_idx,
                        "time_ms": s_idx * sample_interval_ms,
                        "values": vals,
                    },
                    errors=errors,
                )
            )

        metadata: dict = {
            "version": ver,
            "instrument": instrument,
            "sample_interval_ms": sample_interval_ms,
            "channels": channels,
            "start_time_utc": start_time_utc,
            "declared_block_count": decl_blocks,
            "events": events,
        }

        return FileRecoveryResult(
            filename=filename,
            format_name="LABLOG",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=len(recovered_records),
            recovered_records=recovered_records,
            damages=damages,
            metadata=metadata,
        )
