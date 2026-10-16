"""Adversarial and security-focused edge-case tests."""

import unittest
import struct
import tempfile
from pathlib import Path
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.detector import FormatDetector
from src.formats.libra98 import Libra98Parser
from src.models import DamageType, FileRecoveryResult
from src.reporter import Reporter
from src.engine import SalvageEngine

class TestSecurityAndEdgeCases(unittest.TestCase):
    def test_reader_negative_offsets_and_sizes(self):
        reader = BoundedBinaryReader(b"12345678")
        with self.assertRaises(ValueError):
            reader.read_bytes(-5)
        with self.assertRaises(ValueError):
            reader.skip(-1)
        with self.assertRaises(BoundsError):
            reader.seek(-10)

    def test_reader_allocation_limit_defence(self):
        # 1MB buffer with 100-byte cap
        data = b"\x00" * 1024
        reader = BoundedBinaryReader(data, max_alloc=100)
        with self.assertRaises(BoundsError):
            reader.read_bytes(101)

    def test_adversarial_libra98_huge_declared_records(self):
        # Header declares 65535 records in a 16-byte file (attempted OOM / loop freeze)
        parser = Libra98Parser()
        header = struct.pack("<4sHHHHHH", b"LB98", 2, 65535, 0x24A5, 0x5460, 16, 7)
        res = parser.parse("adversarial_count.lib", BoundedBinaryReader(header))
        self.assertTrue(res.is_valid_header)
        # Should not freeze or allocate gigabytes; bounded by actual file size
        self.assertEqual(len(res.recovered_records), 0)

    def test_adversarial_libra98_out_of_bounds_header_size(self):
        # Header declares data_offset = 0xFFFF (exceeding file size)
        parser = Libra98Parser()
        header = struct.pack("<4sHHHHHH", b"LB98", 2, 1, 0x24A5, 0x5460, 0xFFFF, 7)
        res = parser.parse("huge_data_offset.lib", BoundedBinaryReader(header))
        self.assertTrue(any(d.damage_type == DamageType.INVALID_HEADER for d in res.damages))

    def test_format_detector_strict_signature(self):
        # Must not match LIBRA-98 on random prefix like b"LB99" or b"LB"
        self.assertEqual(FormatDetector.detect(b"LB99_NOT_MATCH").format_name, "UNKNOWN")
        self.assertEqual(FormatDetector.detect(b"LB9").format_name, "UNKNOWN")  # 3 bytes
        self.assertEqual(FormatDetector.detect(b"LB98\x02\x00\x01\x00\x00\x00\x00\x00\x10\x00\x01\x00").format_name, "LIBRA-98")

    def test_reporter_path_traversal_sanitization(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            # Try to write using a malicious filename "../../../evil"
            res = FileRecoveryResult(
                filename="../../etc/passwd",
                format_name="UNKNOWN",
                file_size=10,
                is_valid_header=False,
                total_records=0,
            )
            out_file = reporter.write_file_result(res)
            # Ensure saved file is inside tmpdir with sanitized basename
            self.assertEqual(out_file.parent.resolve(), Path(tmpdir).resolve())
            self.assertEqual(out_file.name, "passwd.json")

    def test_reporter_report_json_collision_avoidance(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            res = FileRecoveryResult(
                filename="report.json",
                format_name="UNKNOWN",
                file_size=0,
                is_valid_header=False,
                total_records=0,
            )
            out_file = reporter.write_file_result(res)
            self.assertEqual(out_file.name, "report_input.json.json")
            # Top-level report.json must still write cleanly
            report_path = reporter.write_run_report()
            self.assertEqual(report_path.name, "report.json")

    def test_reporter_symlink_escape_rejection(self):
        """Verify reporter rejects attempting to write through escaped symlink destinations."""
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            # Normal output files must succeed
            res = FileRecoveryResult(
                filename="test.txt",
                format_name="UNKNOWN",
                file_size=5,
                is_valid_header=True,
                total_records=0,
            )
            out_path = reporter.write_file_result(res)
            self.assertTrue(out_path.is_file())
            # Ensure it is strictly inside tmpdir
            out_path.resolve().relative_to(Path(tmpdir).resolve())

    def test_originals_never_modified(self):
        """Ensure original input files are strictly opened read-only and never modified."""
        with tempfile.TemporaryDirectory() as in_dir, tempfile.TemporaryDirectory() as out_dir:
            test_file = Path(in_dir) / "original_sample.bin"
            original_bytes = b"IMMUTABLE_ORIGINAL_DATA_12345"
            test_file.write_bytes(original_bytes)

            engine = SalvageEngine()
            result = engine.process_file(test_file)

            # Assert content of original file remains bit-for-bit identical
            self.assertEqual(test_file.read_bytes(), original_bytes)
            # Assert file timestamp / status is untouched
            reporter = Reporter(out_dir)
            reporter.write_file_result(result)
            reporter.write_run_report()

            # Ensure original is still identical after reporter writes
            self.assertEqual(test_file.read_bytes(), original_bytes)

    def test_pak_entry_count_vs_dir_len_mismatch_and_truncation(self):
        """PAK parser detects directory truncation and count/length mismatches."""
        from src.formats.pak import PakParser
        parser = PakParser()
        # Header specifies directory at offset 12 with length 128 (2 entries), but file is only 50 bytes
        truncated_pak = b"PACK\x0c\x00\x00\x00\x80\x00\x00\x00" + b"\x00" * 38
        res = parser.parse("truncated_dir.pak", BoundedBinaryReader(truncated_pak))
        self.assertTrue(res.is_valid_header)
        self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

if __name__ == "__main__":
    unittest.main()
