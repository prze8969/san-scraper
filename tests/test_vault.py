"""Tests for VAULT format defensive parser conforming to OUTPUT-CONTRACT.md and verified against s08.dat."""

import unittest
import struct
import hashlib
from src.formats.vault import VaultParser, bounded_rle_decompress, DecompressionError
from src.reader import BoundedBinaryReader
from src.models import DamageKind, OutputStatus

def build_real_vault(
    entries: list[tuple[int, str, bytes]], # (id, name, payload)
    xor_key: int = 0x5A,
    corrupt_magic: bool = False,
    truncate_bytes: int = 0,
) -> bytes:
    """Helper to assemble realistic VAULT container files."""
    magic = b"FAIL" if corrupt_magic else b"VLT1"
    entry_count = len(entries)
    flags = 0
    header_size = 16

    # 1. Build Blobs
    blobs_data = bytearray()
    blob_info = [] # (id, name, blob_off, stored_sz, decoded_sz)
    for rec_id, name, payload in entries:
        blob_off = header_size + len(blobs_data)
        blob_hdr = b"BL" + struct.pack("<H", rec_id)
        if name.endswith(".txt"):
            enc_payload = bytes([b ^ ((xor_key + j) & 0xFF) for j, b in enumerate(payload)])
        else:
            enc_payload = payload
        full_blob = blob_hdr + enc_payload
        stored_sz = len(full_blob)
        decoded_sz = len(payload)
        blobs_data.extend(full_blob)
        blob_info.append((rec_id, name, blob_off, stored_sz, decoded_sz))

    # 2. Build Names section
    index_offset = header_size + len(blobs_data)
    names_data = bytearray()
    name_positions = []
    for _, name, _, _, _ in blob_info:
        name_pos = len(names_data)
        name_positions.append(name_pos)
        enc_name = bytes([b ^ ((xor_key + j) & 0xFF) for j, b in enumerate(name.encode("ascii"))])
        names_data.append(len(enc_name))
        names_data.extend(enc_name)

    # 3. Build Index Table (16 bytes per entry)
    index_table = bytearray()
    for (rec_id, name, blob_off, stored_sz, decoded_sz), name_pos in zip(blob_info, name_positions):
        type_code = 1 if name.endswith(".txt") else 2
        flags_code = 0
        entry_raw = struct.pack(
            "<HBBIIHH",
            rec_id,
            type_code,
            flags_code,
            name_pos,
            blob_off,
            stored_sz,
            decoded_sz,
        )
        index_table.extend(entry_raw)

    header = (
        magic
        + struct.pack("<HH", entry_count, xor_key)
        + b"\x00\x00"
        + struct.pack("<H", flags)
        + struct.pack("<I", index_offset)
    )

    full_data = header + blobs_data + names_data + index_table
    if truncate_bytes > 0:
        full_data = full_data[:-truncate_bytes]
    return bytes(full_data)

class TestVaultParser(unittest.TestCase):
    def setUp(self):
        self.parser = VaultParser()

    def test_valid_vault_file(self):
        entries = [
            (1, "notes.txt", b"Confidential system log entries."),
            (2, "data.bin", b"\xDE\xAD\xBE\xEF" * 8),
        ]
        data = build_real_vault(entries, xor_key=0x42)
        res = self.parser.parse("test.vlt", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(res.status, OutputStatus.OK)
        self.assertEqual(len(res.recovered_records), 2)

        r0 = res.recovered_records[0]
        self.assertEqual(r0["id"], 1)
        self.assertEqual(r0["name"], "notes.txt")
        self.assertEqual(r0["type"], "text")
        self.assertEqual(r0["text"], "Confidential system log entries.")
        self.assertEqual(r0["size"], len(b"Confidential system log entries."))
        self.assertEqual(r0["sha256"], hashlib.sha256(b"Confidential system log entries.").hexdigest())

        r1 = res.recovered_records[1]
        self.assertEqual(r1["id"], 2)
        self.assertEqual(r1["name"], "data.bin")
        self.assertEqual(r1["type"], "binary")
        self.assertEqual(len(res.damages), 0)

    def test_corrupt_signature(self):
        data = build_real_vault([], corrupt_magic=True)
        res = self.parser.parse("bad_magic.vlt", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.UNRECOGNIZED)
        self.assertEqual(len(res.recovered_records), 0)

    def test_truncated_header(self):
        data = b"VLT1\x01\x00"
        res = self.parser.parse("trunc_hdr.vlt", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.FAILED)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_truncated_blob_payload(self):
        entries = [(10, "doc.txt", b"Some lengthy text document here")]
        data = build_real_vault(entries, truncate_bytes=10)
        res = self.parser.parse("trunc_blob.vlt", BoundedBinaryReader(data))

        # Because index table is at the end, truncating 10 bytes truncates the index table!
        self.assertEqual(res.status, OutputStatus.PARTIAL)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_rle_decompression_safeguards(self):
        # Test the bounded RLE helper against runaway output
        bomb = b"\x81A" * 10
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(bomb, max_out=500)

if __name__ == "__main__":
    unittest.main()
