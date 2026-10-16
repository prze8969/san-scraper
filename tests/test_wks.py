"""Tests for Lotus 1-2-3 (.WKS) defensive parser conforming to OUTPUT-CONTRACT.md and verified against s11.wks."""

import unittest
import struct
from src.formats.wks import WksParser
from src.reader import BoundedBinaryReader
from src.models import DamageKind, OutputStatus

def build_real_wks(
    records: list[tuple[int, bytes]], # (opcode, payload)
    corrupt_bof: bool = False,
    truncate_bytes: int = 0,
) -> bytes:
    """Helper to assemble realistic Lotus 1-2-3 Release 1A files."""
    bof_opcode = 0x0005 if corrupt_bof else 0x0000
    bof = struct.pack("<HHH", bof_opcode, 2, 0x0404)

    body = bytearray()
    for op, payload in records:
        body.extend(struct.pack("<HH", op, len(payload)))
        body.extend(payload)

    # append EOF record
    body.extend(struct.pack("<HH", 0x0001, 0))

    full_data = bof + body
    if truncate_bytes > 0:
        full_data = full_data[:-truncate_bytes]
    return bytes(full_data)

class TestWksParser(unittest.TestCase):
    def setUp(self):
        self.parser = WksParser()

    def test_valid_wks_cells(self):
        # Build integer cell at col 0, row 0 (A1) = 42
        int_payload = bytes([0x00]) + struct.pack("<HHh", 0, 0, 42)
        # Build label cell at col 1, row 0 (B1) = "Total Revenue"
        lbl_text = b"'Total Revenue\x00"
        lbl_payload = bytes([0xFF]) + struct.pack("<HH", 1, 0) + lbl_text
        # Build number cell at col 1, row 1 (B2) = 1234.56
        num_payload = bytes([0x02]) + struct.pack("<HHd", 1, 1, 1234.56)

        data = build_real_wks([
            (0x000D, int_payload), # INTEGER
            (0x000F, lbl_payload), # LABEL
            (0x000E, num_payload), # NUMBER
        ])
        res = self.parser.parse("sheet.wks", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(res.status, OutputStatus.OK)
        self.assertEqual(len(res.recovered_records), 3)

        # Record 0: A1
        r0 = res.recovered_records[0]
        self.assertEqual(r0["cell"], "A1")
        self.assertEqual(r0["type"], "integer")
        self.assertEqual(r0["value"], 42)

        # Record 1: B1
        r1 = res.recovered_records[1]
        self.assertEqual(r1["cell"], "B1")
        self.assertEqual(r1["type"], "label")
        self.assertEqual(r1["value"], "Total Revenue")
        self.assertEqual(r1["alignment"], "left")

        # Record 2: B2
        r2 = res.recovered_records[2]
        self.assertEqual(r2["cell"], "B2")
        self.assertEqual(r2["type"], "number")
        self.assertEqual(r2["value"], 1234.56)

    def test_corrupt_bof(self):
        data = build_real_wks([], corrupt_bof=True)
        res = self.parser.parse("bad_bof.wks", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.UNRECOGNIZED)
        self.assertEqual(len(res.recovered_records), 0)

    def test_truncated_file(self):
        data = b"\x00\x00\x02"
        res = self.parser.parse("trunc.wks", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.FAILED)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_truncated_cell_record(self):
        int_payload = bytes([0x00]) + struct.pack("<HHh", 0, 0, 99)
        data = build_real_wks([(0x000D, int_payload)], truncate_bytes=5)
        res = self.parser.parse("trunc_rec.wks", BoundedBinaryReader(data))
        # BOF succeeded, but record was truncated
        self.assertEqual(res.status, OutputStatus.PARTIAL)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

if __name__ == "__main__":
    unittest.main()
