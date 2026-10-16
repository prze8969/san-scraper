"""Tests for Quake PAK archive defensive parser conforming to OUTPUT-CONTRACT.md and verified against s24.pak."""

import unittest
import struct
import hashlib
from src.formats.pak import PakParser
from src.reader import BoundedBinaryReader
from src.models import DamageKind, OutputStatus

def build_real_pak(
    files: list[tuple[str, bytes]], # (name, payload)
    corrupt_magic: bool = False,
    truncate_bytes: int = 0,
    dir_len_override: int | None = None,
    entry_size_override: int | None = None,
) -> bytes:
    """Helper to assemble realistic Quake PAK archive files."""
    magic = b"FAIL" if corrupt_magic else b"PACK"

    # Assemble payloads
    payloads = bytearray()
    file_metadata = []
    base_payload_offset = 12

    for fname, content in files:
        f_off = base_payload_offset + len(payloads)
        f_sz = len(content)
        payloads.extend(content)
        file_metadata.append((fname, f_off, f_sz))

    dir_offset = base_payload_offset + len(payloads)
    directory = bytearray()
    for i, (fname, f_off, f_sz) in enumerate(file_metadata):
        name_bytes = fname.encode("ascii")[:56].ljust(56, b"\x00")
        actual_sz = entry_size_override if (entry_size_override is not None and i == len(file_metadata) - 1) else f_sz
        entry = struct.pack("<56sII", name_bytes, f_off, actual_sz)
        directory.extend(entry)

    dir_len = len(directory) if dir_len_override is None else dir_len_override
    header = struct.pack("<4sII", magic, dir_offset, dir_len)

    full_data = header + payloads + directory
    if truncate_bytes > 0:
        full_data = full_data[:-truncate_bytes]
    return bytes(full_data)

class TestPakParser(unittest.TestCase):
    def setUp(self):
        self.parser = PakParser()

    def test_valid_pak_archive(self):
        files = [
            ("maps/e1m1.bsp", b"BSP_BINARY_MAP_DATA_CHUNK"),
            ("progs.dat", b"PROGS_COMPILED_BYTECODE_QUAKE"),
            ("config.cfg", b"bind mouse1 +attack\n"),
        ]
        data = build_real_pak(files)
        res = self.parser.parse("pak0.pak", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(res.status, OutputStatus.OK)
        self.assertEqual(len(res.recovered_records), 3)

        self.assertEqual(res.recovered_records[0]["name"], "maps/e1m1.bsp")
        self.assertEqual(res.recovered_records[0]["size"], len(b"BSP_BINARY_MAP_DATA_CHUNK"))
        self.assertEqual(res.recovered_records[0]["sha256"], hashlib.sha256(b"BSP_BINARY_MAP_DATA_CHUNK").hexdigest())

        self.assertEqual(res.recovered_records[1]["name"], "progs.dat")
        self.assertEqual(res.recovered_records[2]["name"], "config.cfg")
        self.assertEqual(len(res.damages), 0)

    def test_corrupt_signature(self):
        data = build_real_pak([], corrupt_magic=True)
        res = self.parser.parse("bad_magic.pak", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.UNRECOGNIZED)
        self.assertEqual(len(res.recovered_records), 0)

    def test_truncated_header(self):
        data = b"PACK\x04\x00"
        res = self.parser.parse("trunc_hdr.pak", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.FAILED)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_truncated_directory_table(self):
        files = [("test.txt", b"Hello Quake World")]
        data = build_real_pak(files, truncate_bytes=20)
        res = self.parser.parse("trunc_dir.pak", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.PARTIAL)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

    def test_truncated_entry_payload(self):
        files = [
            ("healthy.txt", b"Intact data"),
            ("broken.txt", b"Short"),
        ]
        # Entry declares 5000 bytes, but file ends right after directory table
        data = build_real_pak(files, entry_size_override=5000)
        res = self.parser.parse("trunc_payload.pak", BoundedBinaryReader(data))
        self.assertEqual(res.status, OutputStatus.PARTIAL)
        self.assertTrue(any(d.kind == DamageKind.TRUNCATED for d in res.damages))

if __name__ == "__main__":
    unittest.main()
