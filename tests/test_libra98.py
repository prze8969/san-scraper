"""Tests for LIBRA-98 defensive parser conforming to OUTPUT-CONTRACT.md and verified against s01.dat and s04.dat."""

import unittest
import struct
from src.formats.libra98 import Libra98Parser
from src.reader import BoundedBinaryReader
from src.models import RecordStatus, DamageKind, DamageType, OutputStatus

def build_real_libra98(
    records: list[dict],
    corrupt_magic: bool = False,
    truncate_bytes: int = 0,
    inject_unparsed_before_rec: bytes = b"",
) -> bytes:
    """Helper to assemble realistic LIBRA-98 binary files according to verified ground truth."""
    magic = b"FAIL" if corrupt_magic else b"LB98"
    version = 1
    rec_count = len(records)
    # DOS Date: 2023-05-15 -> ((2023-1980)<<9) | (5<<5) | 15 = (43<<9) | 160 | 15 = 22016 | 160 | 15 = 22191
    dos_date = 22191
    # DOS Time: 14:30:00 -> (14<<11) | (30<<5) = 28672 | 960 = 29632
    dos_time = 29632
    data_offset = 16
    branch_id = 42

    header = struct.pack("<4sHHHHHH", magic, version, rec_count, dos_date, dos_time, data_offset, branch_id)
    body = bytearray()

    for i, rec in enumerate(records):
        if inject_unparsed_before_rec and i == 0:
            body.extend(inject_unparsed_before_rec)

        title_bytes = rec.get("title", "").encode("cp437")
        author_bytes = rec.get("author", "").encode("cp437")
        year_raw = max(0, rec.get("year", 2000) - 1500)
        price_cents = rec.get("price_cents", 1999)
        copies = rec.get("copies", 5)
        isbn_bytes = rec.get("isbn", "0123456789").encode("ascii")[:10].ljust(10, b" ")
        flags = rec.get("flags", 0)

        # payload inside record (after flags)
        payload = bytearray(struct.pack("<I", rec.get("id", 100 + i)))
        payload.append(len(title_bytes))
        payload.extend(title_bytes)
        payload.append(len(author_bytes))
        payload.extend(author_bytes)
        payload.extend(struct.pack("<HHB10s", year_raw, price_cents, copies, isbn_bytes))

        if flags & 0x01: # checked out -> 2-byte due date
            payload.extend(struct.pack("<H", dos_date + 14))

        rec_len = 1 + len(payload) # flags byte + payload length
        rec_header = bytearray([0xA5, rec_len, flags])
        body.extend(rec_header)
        body.extend(payload)

    body.extend(b"END!\x00\x00")

    full_data = header + body
    if truncate_bytes > 0:
        full_data = full_data[:-truncate_bytes]
    return bytes(full_data)

class TestLibra98Parser(unittest.TestCase):
    def setUp(self):
        self.parser = Libra98Parser()

    def test_valid_libra98_file(self):
        records = [
            {
                "id": 1001,
                "title": "Clean Code",
                "author": "Robert C. Martin",
                "year": 2008,
                "price_cents": 3499,
                "copies": 3,
                "isbn": "0132350882",
                "flags": 0,
            },
            {
                "id": 1002,
                "title": "The Pragmatic Programmer",
                "author": "David Thomas",
                "year": 1999,
                "price_cents": 4200,
                "copies": 0,
                "isbn": "020161622X",
                "flags": 0x01,  # checked out
            },
        ]
        data = build_real_libra98(records)
        res = self.parser.parse("test.lib", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(res.status, OutputStatus.OK)
        self.assertEqual(len(res.recovered_records), 2)
        self.assertEqual(res.recovered_records[0]["title"], "Clean Code")
        self.assertEqual(res.recovered_records[0]["author"], "Robert C. Martin")
        self.assertEqual(res.recovered_records[0]["year"], 2008)
        self.assertEqual(res.recovered_records[0]["price_cents"], 3499)
        self.assertEqual(res.recovered_records[0]["checked_out"], False)
        self.assertEqual(res.recovered_records[1]["checked_out"], True)
        self.assertIsNotNone(res.recovered_records[1]["due_date"])
        self.assertEqual(len(res.damages), 0)

    def test_corrupt_signature(self):
        data = build_real_libra98([], corrupt_magic=True)
        res = self.parser.parse("corrupt_magic.lib", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.UNRECOGNIZED)
        self.assertEqual(len(res.recovered_records), 0)

    def test_truncated_header(self):
        data = b"LB98\x01\x00"
        res = self.parser.parse("trunc_hdr.lib", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.FAILED)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_unparsed_bytes_recovery(self):
        records = [{"id": 501, "title": "Recovered Book", "author": "Anonymous", "year": 2010}]
        data = build_real_libra98(records, inject_unparsed_before_rec=b"\xDE\xAD\xBE\xEF\x00\xFF")
        res = self.parser.parse("unparsed.lib", BoundedBinaryReader(data))

        self.assertEqual(len(res.recovered_records), 1)
        self.assertEqual(res.recovered_records[0]["title"], "Recovered Book")
        self.assertTrue(any(d.kind == DamageKind.UNPARSED_BYTES for d in res.damages))
        self.assertEqual(res.status, OutputStatus.PARTIAL)

    def test_truncated_record_payload(self):
        records = [
            {"id": 1, "title": "First Book", "author": "A", "year": 2001},
            {"id": 2, "title": "Second Book", "author": "B", "year": 2002},
        ]
        data = build_real_libra98(records, truncate_bytes=15)
        res = self.parser.parse("truncated.lib", BoundedBinaryReader(data))

        # First record recovered completely, second truncated
        self.assertEqual(len(res.recovered_records), 1)
        self.assertEqual(res.recovered_records[0]["title"], "First Book")
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))
        self.assertEqual(res.status, OutputStatus.PARTIAL)

if __name__ == "__main__":
    unittest.main()
