"""Unit and fuzz tests for documented legacy/archive formats:
1. Doom WAD (IWAD/PWAD): Header, lump directory, zero-length markers, out-of-range lump offsets.
   Source: id Software Doom source release (w_wad.c / doomdef.h).
2. ZIP: Local file header (PK\\x03\\x04), central directory fallback recovery, CRC32, stored/deflate, decompression bomb cap, path traversal.
   Source: PKWARE APPNOTE.TXT (Section 4.3).
3. GZIP: RFC 1952 header, flags, deflate stream, CRC32 trailer, ISIZE validation.
   Source: IETF RFC 1952 (GZIP file format specification version 4.3).
4. PNG: ISO/IEC 15948 chunk framing (8-byte header, chunk length, chunk type, CRC32).
   Source: ISO/IEC 15948:2004 / W3C Portable Network Graphics (PNG) Specification (Second Edition).
"""

import os
import struct
import zlib
import random
import unittest
from pathlib import Path
import tempfile
import shutil

from src.reader import BoundedBinaryReader
from src.formats.wad import WadParser
from src.formats.zip import ZipParser
from src.formats.gzip import GzipParser
from src.formats.png import PngParser
from src.engine import SalvageEngine
from src.models import RecordStatus


class TestDoomWadParser(unittest.TestCase):
    """Doom WAD layout tests according to id Software Doom specs:
    Header: 4-byte identification ('IWAD' or 'PWAD'), 4-byte numlumps (LE uint32), 4-byte infotableofs (LE uint32).
    Directory entry: 4-byte filepos (LE uint32), 4-byte size (LE uint32), 8-byte name (ASCII, null-padded).
    """

    def test_valid_iwad_recovery(self):
        # Reference: id Software doomdef.h
        lump1_data = b"E1M1_HEX_MAP_DATA_12345678"
        lump2_data = b""  # Marker lump (e.g. F_START)
        lump3_data = b"PLAYPAL_PALETTE_DATA"

        header_len = 12
        lump1_pos = header_len
        lump2_pos = lump1_pos + len(lump1_data)
        lump3_pos = lump2_pos + len(lump2_data)
        dir_pos = lump3_pos + len(lump3_data)

        # Build directory (3 lumps * 16 bytes = 48 bytes)
        dir_entry1 = struct.pack("<II8s", lump1_pos, len(lump1_data), b"E1M1\x00\x00\x00\x00")
        dir_entry2 = struct.pack("<II8s", lump2_pos, len(lump2_data), b"F_START\x00")
        dir_entry3 = struct.pack("<II8s", lump3_pos, len(lump3_data), b"PLAYPAL\x00")

        header = struct.pack("<4sII", b"IWAD", 3, dir_pos)
        wad_bytes = header + lump1_data + lump2_data + lump3_data + dir_entry1 + dir_entry2 + dir_entry3

        parser = WadParser()
        result = parser.parse("doom1.wad", BoundedBinaryReader(wad_bytes))

        self.assertEqual(result.format_name, "WAD")
        self.assertEqual(len(result.recovered_records), 3)
        self.assertEqual(result.recovered_records[0].fields["name"], "E1M1")
        self.assertEqual(result.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[1].fields["name"], "F_START")
        self.assertEqual(result.recovered_records[1].fields["is_marker"], True)
        self.assertEqual(result.recovered_records[1].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[2].fields["name"], "PLAYPAL")
        self.assertEqual(result.recovered_records[2].status, RecordStatus.COMPLETE)
        self.assertEqual(len(result.damages), 0)

    def test_wad_truncated_directory_and_out_of_bounds_lump(self):
        # Header specifies 3 lumps, but directory only has 1 complete entry and an out-of-bounds lump
        header = struct.pack("<4sII", b"PWAD", 3, 12)
        dir_entry1 = struct.pack("<II8s", 9999, 100, b"BADLUMP\x00")
        dir_entry2 = struct.pack("<II", 100, 50)

        data = header + dir_entry1 + dir_entry2
        parser = WadParser()
        result = parser.parse("corrupt.wad", BoundedBinaryReader(data))

        self.assertEqual(result.format_name, "WAD")
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.UNRECOVERABLE)
        self.assertTrue(len(result.damages) >= 2)


class TestZipParser(unittest.TestCase):
    """ZIP layout tests according to PKWARE APPNOTE.TXT:
    Local file header: 'PK\\x03\\x04', version (2B), bit flag (2B), comp method (2B),
    mod time (2B), mod date (2B), crc32 (4B), comp size (4B), uncomp size (4B),
    fname len (2B), extra len (2B), fname, extra, compressed data.
    """

    def test_valid_stored_and_deflated_zip(self):
        # File 1: Stored (method 0)
        content1 = b"Hello uncompressed world!"
        fname1 = b"hello.txt"
        crc1 = zlib.crc32(content1)
        lfh1 = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, crc1, len(content1), len(content1), len(fname1), 0) + fname1 + content1

        # File 2: Deflated (method 8)
        content2 = b"Repeat data " * 50
        comp2 = zlib.compress(content2)[2:-4]  # Raw deflate without zlib wrapper
        fname2 = b"sub/repeat.txt"
        crc2 = zlib.crc32(content2)
        lfh2 = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, crc2, len(comp2), len(content2), len(fname2), 0) + fname2 + comp2

        zip_bytes = lfh1 + lfh2
        parser = ZipParser()
        result = parser.parse("archive.zip", BoundedBinaryReader(zip_bytes))

        self.assertEqual(result.format_name, "ZIP")
        self.assertEqual(len(result.recovered_records), 2)
        self.assertEqual(result.recovered_records[0].fields["name"], "hello.txt")
        self.assertEqual(result.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[0].fields["decompressed_data"], content1)

        self.assertEqual(result.recovered_records[1].fields["name"], "sub/repeat.txt")
        self.assertEqual(result.recovered_records[1].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[1].fields["decompressed_data"], content2)

    def test_zip_local_headers_recovery_without_central_directory(self):
        content = b"Salvaged from local header alone"
        fname = b"rescued.txt"
        crc = zlib.crc32(content)
        lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, len(content), len(content), len(fname), 0) + fname + content

        parser = ZipParser()
        result = parser.parse("damaged_cd.zip", BoundedBinaryReader(lfh))
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[0].fields["decompressed_data"], content)

    def test_zip_bad_crc_and_path_traversal(self):
        content = b"Malicious payload or corrupted data"
        fname = b"../../../../etc/passwd"
        bad_crc = 0x12345678
        lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, bad_crc, len(content), len(content), len(fname), 0) + fname + content

        parser = ZipParser()
        result = parser.parse("traversal.zip", BoundedBinaryReader(lfh))
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.CORRUPTED)
        self.assertEqual(result.recovered_records[0].fields["crc_status"], "mismatch")

        clean_name, was_traversal = ZipParser.sanitize_name(result.recovered_records[0].fields["name"])
        self.assertFalse(clean_name.startswith(".."))
        self.assertNotIn("..", clean_name.split("/"))

    def test_zip_decompression_bomb_mitigation(self):
        comp = b"\x00" * 10
        fname = b"bomb.bin"
        huge_size = 50 * 1024 * 1024
        lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, 0, len(comp), huge_size, len(fname), 0) + fname + comp

        parser = ZipParser()
        result = parser.parse("bomb.zip", BoundedBinaryReader(lfh))
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.PARTIAL)
        self.assertTrue(any("exceeds safety cap" in err.lower() for err in result.recovered_records[0].errors))


class TestGzipParser(unittest.TestCase):
    """GZIP layout tests according to RFC 1952:
    Header: ID1 (0x1F), ID2 (0x8B), CM (8 = deflate), FLG, MTIME (4B), XFL, OS.
    Trailer: CRC32 (4B), ISIZE (4B).
    """

    def test_valid_gzip_stream(self):
        payload = b"Testing GZIP compression layout RFC 1952 standard."
        import gzip
        gz_bytes = gzip.compress(payload)

        parser = GzipParser()
        result = parser.parse("stream.gz", BoundedBinaryReader(gz_bytes))
        self.assertEqual(result.format_name, "GZIP")
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[0].fields["decompressed_data"], payload)
        self.assertEqual(result.recovered_records[0].fields["crc_status"], "verified")

    def test_gzip_corrupted_crc_trailer(self):
        payload = b"Data with altered trailer."
        import gzip
        gz_bytes = bytearray(gzip.compress(payload))
        gz_bytes[-8] ^= 0xFF

        parser = GzipParser()
        result = parser.parse("bad_trailer.gz", BoundedBinaryReader(bytes(gz_bytes)))
        self.assertEqual(result.format_name, "GZIP")
        self.assertEqual(len(result.recovered_records), 1)
        self.assertEqual(result.recovered_records[0].status, RecordStatus.CORRUPTED)
        self.assertEqual(result.recovered_records[0].fields["crc_status"], "mismatch")

    def test_gzip_truncated_data(self):
        payload = b"Truncated gzip stream"
        import gzip
        gz_bytes = gzip.compress(payload)
        truncated = gz_bytes[:15]

        parser = GzipParser()
        result = parser.parse("cut.gz", BoundedBinaryReader(truncated))
        self.assertEqual(result.format_name, "GZIP")
        self.assertTrue(len(result.damages) > 0)


class TestPngParser(unittest.TestCase):
    """PNG layout tests according to ISO/IEC 15948:
    Signature: 89 50 4E 47 0D 0A 1A 0A
    Chunk: Length (4B BE uint32), Chunk Type (4B ASCII), Chunk Data, CRC (4B BE uint32).
    """

    def test_valid_png_chunks(self):
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
        ihdr_chunk = struct.pack(">I4s", len(ihdr_data), b"IHDR") + ihdr_data + struct.pack(">I", ihdr_crc)

        raw_scanline = b"\x00\xff\x00\x00"
        idat_data = zlib.compress(raw_scanline)
        idat_crc = zlib.crc32(b"IDAT" + idat_data)
        idat_chunk = struct.pack(">I4s", len(idat_data), b"IDAT") + idat_data + struct.pack(">I", idat_crc)

        iend_crc = zlib.crc32(b"IEND")
        iend_chunk = struct.pack(">I4s", 0, b"IEND") + struct.pack(">I", iend_crc)

        png_bytes = sig + ihdr_chunk + idat_chunk + iend_chunk
        parser = PngParser()
        result = parser.parse("pixel.png", BoundedBinaryReader(png_bytes))

        self.assertEqual(result.format_name, "PNG")
        self.assertEqual(len(result.recovered_records), 3)
        self.assertEqual([r.fields["chunk_type"] for r in result.recovered_records], ["IHDR", "IDAT", "IEND"])
        self.assertTrue(all(r.status == RecordStatus.COMPLETE for r in result.recovered_records))
        self.assertEqual(len(result.damages), 0)

    def test_png_corrupted_chunk_crc_preserves_intact_chunks(self):
        sig = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc = zlib.crc32(b"IHDR" + ihdr_data)
        ihdr_chunk = struct.pack(">I4s", len(ihdr_data), b"IHDR") + ihdr_data + struct.pack(">I", ihdr_crc)

        idat_data = b"Corrupted data chunk"
        bad_crc = 0xDEADBEEF
        idat_chunk = struct.pack(">I4s", len(idat_data), b"IDAT") + idat_data + struct.pack(">I", bad_crc)

        iend_crc = zlib.crc32(b"IEND")
        iend_chunk = struct.pack(">I4s", 0, b"IEND") + struct.pack(">I", iend_crc)

        png_bytes = sig + ihdr_chunk + idat_chunk + iend_chunk
        parser = PngParser()
        result = parser.parse("damaged.png", BoundedBinaryReader(png_bytes))

        self.assertEqual(len(result.recovered_records), 3)
        self.assertEqual(result.recovered_records[0].fields["chunk_type"], "IHDR")
        self.assertEqual(result.recovered_records[0].status, RecordStatus.COMPLETE)
        self.assertEqual(result.recovered_records[1].fields["chunk_type"], "IDAT")
        self.assertEqual(result.recovered_records[1].status, RecordStatus.CORRUPTED)
        self.assertEqual(result.recovered_records[1].fields["crc_status"], "mismatch")
        self.assertEqual(result.recovered_records[2].fields["chunk_type"], "IEND")
        self.assertEqual(result.recovered_records[2].status, RecordStatus.COMPLETE)


class TestContainerExtraction(unittest.TestCase):
    """Test disk extraction to <output_dir>/<name>.extracted/ for PAK, WAD, and ZIP."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_pak_extraction_to_disk(self):
        entry_data = b"Extracted file data!"
        header = struct.pack("<4sII", b"PACK", 12 + len(entry_data), 64)
        dir_entry = struct.pack("<56sII", b"docs/readme.txt\x00", 12, len(entry_data))
        pak_bytes = header + entry_data + dir_entry

        engine = SalvageEngine()
        result = engine.process_bytes("test.pak", pak_bytes, output_dir=self.test_dir)

        extracted_dir = Path(self.test_dir) / "test.pak.extracted"
        self.assertTrue(extracted_dir.exists())
        target_file = extracted_dir / "docs" / "readme.txt"
        self.assertTrue(target_file.exists())
        self.assertEqual(target_file.read_bytes(), entry_data)

    def test_zip_extraction_prevents_directory_traversal(self):
        content = b"Should stay safely quarantined"
        fname = b"../../malicious.txt"
        crc = zlib.crc32(content)
        lfh = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, crc, len(content), len(content), len(fname), 0) + fname + content

        engine = SalvageEngine()
        result = engine.process_bytes("archive.zip", lfh, output_dir=self.test_dir)

        extracted_dir = Path(self.test_dir) / "archive.zip.extracted"
        self.assertTrue(extracted_dir.exists())
        sanitized_file = extracted_dir / "malicious.txt"
        self.assertTrue(sanitized_file.exists())
        outside_file = Path(self.test_dir) / "malicious.txt"
        self.assertFalse(outside_file.exists())


class TestParserSeededFuzzing(unittest.TestCase):
    """Seeded fuzz testing per parser: ensures no crash or hang on random inputs."""

    def test_fuzz_known_parsers(self):
        rng = random.Random(42)
        parsers = [WadParser(), ZipParser(), GzipParser(), PngParser()]

        for parser in parsers:
            for iteration in range(50):
                length = rng.randint(0, 2048)
                fuzz_data = rng.randbytes(length)
                try:
                    res = parser.parse("fuzz.bin", BoundedBinaryReader(fuzz_data))
                    self.assertIsNotNone(res)
                except Exception as e:
                    self.fail(f"Parser {parser.__class__.__name__} crashed on fuzz iteration {iteration}: {e}")


if __name__ == "__main__":
    unittest.main()
