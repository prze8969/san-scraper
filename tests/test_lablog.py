"""Tests for LABLOG defensive parser conforming to OUTPUT-CONTRACT.md and verified against s05.dat."""

import unittest
import struct
from src.formats.lablog import LablogParser
from src.reader import BoundedBinaryReader
from src.models import DamageKind, OutputStatus

def build_real_lablog(
    channels: list[tuple[str, float, float]], # (unit, slope, intercept)
    data_samples: list[list[int]], # raw integer values for each sample
    events: list[tuple[int, int, str]] | None = None, # (sample, severity, message)
    corrupt_magic: bool = False,
    truncate_bytes: int = 0,
    inject_unparsed: bytes = b"",
) -> bytes:
    """Helper to assemble realistic LABLOG binary files."""
    magic = b"FAIL" if corrupt_magic else b"LLOG"
    version = 1
    num_channels = len(channels)
    interval_raw = 5 # 50 ms
    inst_name = b"SPEC-METER-9000".ljust(16, b"\x00")
    start_ts_raw = 100000000 # offset from 1990 epoch
    declared_blocks = 1 + (1 if events else 0)

    def calc_crc(buf: bytes) -> bytes:
        crc = 0xFFFF
        for b in buf:
            crc ^= (b << 8)
            for _ in range(8):
                if crc & 0x8000:
                    crc = ((crc << 1) ^ 0x1021) & 0xFFFF
                else:
                    crc = (crc << 1) & 0xFFFF
        return struct.pack("<H", crc)

    hdr_fixed_30 = (
        magic
        + bytes([version, num_channels])
        + struct.pack("<H", interval_raw)
        + inst_name
        + struct.pack("<IH", start_ts_raw, declared_blocks)
    )
    hdr_crc = calc_crc(hdr_fixed_30)

    ch_bytes = bytearray()
    for unit, slope, intercept in channels:
        ch_bytes.extend(unit.encode("ascii")[:4].ljust(4, b"\x00"))
        ch_bytes.extend(struct.pack("<ff", slope, intercept))

    # Channels block: 0xB1 + 0x03 + len + ch_bytes + crc
    ch_block_body = bytes([3]) + struct.pack("<H", len(ch_bytes)) + ch_bytes
    ch_block = bytes([0xB1]) + ch_block_body + calc_crc(ch_block_body)

    header = hdr_fixed_30 + hdr_crc + ch_block

    body = bytearray()
    if inject_unparsed:
        body.extend(inject_unparsed)

    # 1. Data Block
    if data_samples:
        count = len(data_samples)
        start_sample = 0
        raw_payload = bytearray(struct.pack("<HB", start_sample, count))
        for s in data_samples:
            for val in s:
                raw_payload.extend(struct.pack("<h", val))
        
        b_len = len(raw_payload)
        blk_body = bytes([1]) + struct.pack("<H", b_len) + raw_payload
        blk = bytes([0xB1]) + blk_body + calc_crc(blk_body)
        body.extend(blk)

    # 2. Event Block
    if events:
        for ev_sample, ev_sev, ev_msg in events:
            msg_bytes = ev_msg.encode("ascii")
            ev_payload = struct.pack("<HBB", ev_sample, ev_sev, len(msg_bytes)) + msg_bytes
            b_len = len(ev_payload)
            blk_body = bytes([2]) + struct.pack("<H", b_len) + ev_payload
            blk = bytes([0xB1]) + blk_body + calc_crc(blk_body)
            body.extend(blk)

    full_data = header + body
    if truncate_bytes > 0:
        full_data = full_data[:-truncate_bytes]
    return bytes(full_data)

class TestLablogParser(unittest.TestCase):
    def setUp(self):
        self.parser = LablogParser()

    def test_valid_lablog_file(self):
        channels = [
            ("mV", 0.1, 5.0),
            ("mA", 0.01, 0.0),
        ]
        samples = [
            [100, 200],
            [150, 250],
        ]
        events = [(1, 2, "Voltage spike detected")]
        data = build_real_lablog(channels, samples, events)
        res = self.parser.parse("valid.lab", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(res.status, OutputStatus.OK)
        self.assertEqual(len(res.recovered_records), 2)
        # sample 0: 100 * 0.1 + 5.0 = 15.0; 200 * 0.01 + 0.0 = 2.0
        self.assertEqual(res.recovered_records[0]["sample"], 0)
        self.assertEqual(res.recovered_records[0]["time_ms"], 0)
        self.assertEqual(res.recovered_records[0]["values"], [15.0, 2.0])

        self.assertEqual(res.recovered_records[1]["sample"], 1)
        self.assertEqual(res.recovered_records[1]["time_ms"], 50)
        self.assertEqual(res.recovered_records[1]["values"], [20.0, 2.5])

        # verify metadata
        self.assertEqual(res.metadata["instrument"], "SPEC-METER-9000")
        self.assertEqual(res.metadata["sample_interval_ms"], 50)
        self.assertEqual(len(res.metadata["events"]), 1)
        self.assertEqual(res.metadata["events"][0]["message"], "Voltage spike detected")

    def test_corrupt_signature(self):
        data = build_real_lablog([("mV", 1.0, 0.0)], [[10]], corrupt_magic=True)
        res = self.parser.parse("bad_magic.lab", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.UNRECOGNIZED)
        self.assertEqual(len(res.recovered_records), 0)

    def test_truncated_header(self):
        data = b"LLOG\x01\x01\x05"
        res = self.parser.parse("trunc_hdr.lab", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.FAILED)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_desynchronized_stream_recovery(self):
        channels = [("V", 1.0, 0.0)]
        samples = [[42]]
        data = build_real_lablog(channels, samples, inject_unparsed=b"\x00\xFF\xAA\x55")
        res = self.parser.parse("desync.lab", BoundedBinaryReader(data))

        self.assertEqual(res.status, OutputStatus.PARTIAL)
        self.assertEqual(len(res.recovered_records), 1)
        self.assertEqual(res.recovered_records[0]["values"], [42.0])
        self.assertTrue(any(d.kind == DamageKind.UNPARSED_BYTES for d in res.damages))

    def test_dropout_handling(self):
        channels = [("V", 1.0, 0.0)]
        samples = [[-32768]] # dropout sentinel
        data = build_real_lablog(channels, samples)
        res = self.parser.parse("dropout.lab", BoundedBinaryReader(data))

        self.assertEqual(len(res.recovered_records), 1)
        self.assertEqual(res.recovered_records[0]["values"], [None])

if __name__ == "__main__":
    unittest.main()
