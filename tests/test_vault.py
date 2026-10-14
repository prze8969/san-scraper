"""Tests for VAULT defensive parser, bounded RLE, and XOR deobfuscation."""

import unittest
import struct
import zlib
from src.formats.vault import (
    VaultParser,
    bounded_rle_decompress,
    xor_deobfuscate,
    DecompressionError,
)
from src.reader import BoundedBinaryReader
from src.models import RecordStatus, DamageType

def encode_packbits_rle(data: bytes) -> bytes:
    """Helper to encode byte stream into PackBits/Byte-Run RLE."""
    out = bytearray()
    i = 0
    n = len(data)

    while i < n:
        # Check for repeated bytes
        run_len = 1
        while i + run_len < n and data[i + run_len] == data[i] and run_len < 128:
            run_len += 1

        if run_len >= 3:
            # Repeat run: control byte = 257 - run_len
            ctrl = 257 - run_len
            out.append(ctrl)
            out.append(data[i])
            i += run_len
        else:
            # Literal run
            lit_start = i
            while i < n and (i + 1 >= n or data[i] != data[i + 1] or (i + 2 < n and data[i] != data[i + 2])) and (i - lit_start < 128):
                i += 1
            lit_len = i - lit_start
            if lit_len > 0:
                ctrl = lit_len - 1
                out.append(ctrl)
                out.extend(data[lit_start:i])

    return bytes(out)

def build_synthetic_vault(
    entries: list[dict],  # list of {id, name, data, rle: bool, xor_key: int, corrupt_crc: bool}
    corrupt_hdr_crc: bool = False,
    corrupt_index_offset: bool = False,
    truncate_bytes: int = 0,
) -> bytes:
    """Helper to assemble a synthetic VAULT binary archive."""
    magic = b"VAULT\x01\x00\x00"
    version = 1
    flags = 0
    entry_count = len(entries)
    global_xor = 0x5A5A5A5A

    # Build blob payloads
    blob_headers = []
    blobs_data = bytearray()
    curr_blob_offset = 32  # header is 32 bytes

    for entry in entries:
        raw_data = entry["data"]
        rle = entry.get("rle", False)
        xor_k = entry.get("xor_key", 0)

        # If RLE requested, compress first, then XOR
        processed = raw_data
        eflags = 0x04  # UTF8
        if rle:
            processed = encode_packbits_rle(processed)
            eflags |= 0x01
        if xor_k > 0:
            processed = bytes(b ^ xor_k for b in processed)
            eflags |= 0x02

        stored_size = len(processed)
        decoded_size = len(raw_data)
        blob_offset = curr_blob_offset + len(blobs_data)
        blobs_data.extend(processed)

        crc = zlib.crc32(raw_data) & 0xFFFFFFFF
        if entry.get("corrupt_crc", False):
            crc ^= 0xDEADBEEF

        blob_headers.append({
            "id": entry["id"],
            "offset": blob_offset,
            "stored_size": stored_size,
            "decoded_size": decoded_size,
            "flags": eflags,
            "xor_key": xor_k,
            "name": entry["name"],
            "crc": crc,
        })

    # Index table follows blobs
    index_offset = curr_blob_offset + len(blobs_data)
    index_len = len(blob_headers) * 48

    # Assemble Index table
    index_bytes = bytearray()
    for bh in blob_headers:
        name_bytes = bh["name"].encode("utf-8")[:24].ljust(24, b"\x00")
        entry_row = struct.pack(
            "<IIIIHBB24sI",
            bh["id"],
            bh["offset"],
            bh["stored_size"],
            bh["decoded_size"],
            bh["flags"],
            bh["xor_key"],
            0,
            name_bytes,
            bh["crc"],
        )
        index_bytes.extend(entry_row)

    # Assemble Header
    actual_index_off = index_offset if not corrupt_index_offset else 0x00FFFFFF
    hdr_pre = struct.pack("<8sHHIII", magic, version, flags, entry_count, actual_index_off, index_len)
    hdr_crc = zlib.crc32(hdr_pre) & 0xFFFFFFFF
    if corrupt_hdr_crc:
        hdr_crc ^= 0xBADF00D
    header = hdr_pre + struct.pack("<II", hdr_crc, global_xor)

    full_archive = header + blobs_data + index_bytes
    if truncate_bytes > 0:
        full_archive = full_archive[:-truncate_bytes]
    return bytes(full_archive)

class TestVaultParser(unittest.TestCase):
    def setUp(self):
        self.parser = VaultParser()

    def test_rle_decompression_primitives(self):
        # 1. Literal run: [2, 'A', 'B', 'C'] -> "ABC"
        lit_stream = bytes([2, ord("A"), ord("B"), ord("C")])
        self.assertEqual(bounded_rle_decompress(lit_stream), b"ABC")

        # 2. Repeat run: [257 - 5 = 252, 'Z'] -> "ZZZZZ"
        rep_stream = bytes([252, ord("Z")])
        self.assertEqual(bounded_rle_decompress(rep_stream), b"ZZZZZ")

        # 3. Allocation bounds enforcement
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(rep_stream, max_output_size=3)

        # 4. Truncated stream
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(bytes([5, ord("X")]))  # claims 6 literals, only 1 byte follows

    def test_xor_deobfuscation_primitive(self):
        plain = b"Secret Plan"
        obfuscated = bytes(b ^ 0x42 for b in plain)
        self.assertEqual(xor_deobfuscate(obfuscated, 0x42), plain)
        self.assertEqual(xor_deobfuscate(plain, 0), plain)

    # --- Self-consistency tests (generated via project's build_synthetic_vault helper) ---

    def test_self_consistency_valid_synthetic_vault_archive(self):
        """[self-consistency] Valid VAULT archive generated by internal helper."""
        entries = [
            {"id": 1, "name": "readme.txt", "data": b"Welcome to VAULT test.", "rle": False, "xor_key": 0},
            {"id": 2, "name": "rle_compressed.dat", "data": b"AAAAABBBBBCCCCCDDDDD", "rle": True, "xor_key": 0},
            {"id": 3, "name": "xor_secret.txt", "data": b"Top secret operational directive.", "rle": False, "xor_key": 0x37},
            {"id": 4, "name": "both.dat", "data": b"ZZZZZZZZZZ9999999999", "rle": True, "xor_key": 0x19},
        ]
        data = build_synthetic_vault(entries)
        res = self.parser.parse("archive.vlt", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(len(res.recovered_records), 4)
        self.assertEqual(len(res.damages), 0)
        self.assertEqual(res.recovered_records[0].fields["text"], "Welcome to VAULT test.")
        self.assertEqual(res.recovered_records[1].fields["text"], "AAAAABBBBBCCCCCDDDDD")
        self.assertEqual(res.recovered_records[2].fields["text"], "Top secret operational directive.")
        self.assertEqual(res.recovered_records[3].fields["text"], "ZZZZZZZZZZ9999999999")

    def test_self_consistency_corrupt_entry_crc_isolation(self):
        """[self-consistency] Per-entry CRC32 isolation via helper."""
        entries = [
            {"id": 1, "name": "file1.txt", "data": b"Healthy record 1", "rle": False, "xor_key": 0},
            {"id": 2, "name": "file2.txt", "data": b"Corrupted record 2", "rle": False, "xor_key": 0, "corrupt_crc": True},
            {"id": 3, "name": "file3.txt", "data": b"Healthy record 3", "rle": False, "xor_key": 0},
        ]
        data = build_synthetic_vault(entries)
        res = self.parser.parse("partial_corrupt.vlt", BoundedBinaryReader(data))

        self.assertEqual(len(res.recovered_records), 3)
        self.assertEqual(res.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(res.recovered_records[1].status, RecordStatus.CORRUPTED)
        self.assertEqual(res.recovered_records[2].status, RecordStatus.COMPLETE)
        self.assertTrue(any(d.damage_type == DamageType.CHECKSUM_MISMATCH for d in res.damages))

    def test_self_consistency_malformed_index_offset(self):
        """[self-consistency] Out-of-bounds index offset handling."""
        entries = [{"id": 1, "name": "a.txt", "data": b"Data", "rle": False}]
        data = build_synthetic_vault(entries, corrupt_index_offset=True)
        res = self.parser.parse("bad_index.vlt", BoundedBinaryReader(data))

        self.assertTrue(res.is_valid_header)
        self.assertEqual(len(res.recovered_records), 0)
        self.assertTrue(any(d.damage_type == DamageType.MALFORMED_OFFSET for d in res.damages))

    def test_self_consistency_truncated_archive(self):
        """[self-consistency] Truncated archive in index table."""
        entries = [{"id": 1, "name": "a.txt", "data": b"Data"*20, "rle": False}]
        data = build_synthetic_vault(entries, truncate_bytes=30)
        res = self.parser.parse("trunc.vlt", BoundedBinaryReader(data))
        self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    # --- Independent fixtures (hand-assembled byte string according to provisional spec) ---

    def test_independent_handcrafted_vault_spec(self):
        """
        [independent] Hand-assembled VAULT archive binary using explicit byte definitions.
        Layout:
          Header (32B):
            Magic: b'VAULT\x01\x00\x00' (8B)
            Version: 1 (2B LE) = \x01\x00
            Flags: 0 (2B LE) = \x00\x00
            Entry Count: 1 (4B LE) = \x01\x00\x00\x00
            Index Offset: 32 + 10 = 42 (4B LE)
            Index Length: 48 (4B LE)
            Header CRC32 over bytes 0..23
            Global XOR Key: 0
          Payload (10B at offset 32):
            b'INDEP_DATA'
          Index Entry (48B at offset 42):
            Entry ID: 100 (4B LE)
            Blob Offset: 32 (4B LE)
            Stored Size: 10 (4B LE)
            Decoded Size: 10 (4B LE)
            Flags: 0x04 (UTF8 uncompressed)
            XOR Key Byte: 0
            Reserved: 0
            Entry Name: b'indep.txt\0' (24B)
            Entry CRC32 over b'INDEP_DATA'
        """
        magic = b"VAULT\x01\x00\x00"
        hdr_pre = struct.pack("<8sHHIII", magic, 1, 0, 1, 42, 48)
        hdr_crc = zlib.crc32(hdr_pre) & 0xFFFFFFFF
        header = hdr_pre + struct.pack("<II", hdr_crc, 0)
        self.assertEqual(len(header), 32)

        payload = b"INDEP_DATA"
        payload_crc = zlib.crc32(payload) & 0xFFFFFFFF

        name_bytes = b"indep.txt" + b"\x00" * (24 - len(b"indep.txt"))
        index_entry = struct.pack("<IIIIHBB24sI", 100, 32, 10, 10, 0x04, 0, 0, name_bytes, payload_crc)
        self.assertEqual(len(index_entry), 48)

        handcrafted = header + payload + index_entry
        self.assertEqual(len(handcrafted), 32 + 10 + 48)

        res = self.parser.parse("independent_vault.vlt", BoundedBinaryReader(handcrafted))
        self.assertTrue(res.is_valid_header)
        self.assertEqual(len(res.recovered_records), 1)
        self.assertEqual(res.recovered_records[0].fields["name"], "indep.txt")
        self.assertEqual(res.recovered_records[0].fields["text"], "INDEP_DATA")
        self.assertEqual(res.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(len(res.damages), 0)

if __name__ == "__main__":
    unittest.main()
