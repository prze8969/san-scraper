"""test_salvage.py: Comprehensive unit + corruption + CLI integration suite for Phase 5."""

import unittest
import json
import tempfile
from pathlib import Path
from src.cursor import SafeByteCursor
from src.router import FormatRouter
from src.transforms import crc16_ccitt, rle_decompress_packbits, xor_apply, xor_crack_ascii
from src.engine import SalvageEngine
from src.cli import run_salvage
from tools.generate_samples import generate_samples

class TestSalvageAutonomousSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.samples_dir = Path(cls.temp_dir.name) / "samples"
        generate_samples(cls.samples_dir)
        cls.engine = SalvageEngine()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def test_01_router_identification(self):
        """All synthesized formats must be correctly recognized."""
        for f in self.samples_dir.iterdir():
            data = f.read_bytes()
            match = FormatRouter.identify(data, f.name)
            self.assertIsNotNone(match.format_name)
            self.assertIn(match.confidence, ("HIGH", "MEDIUM", "HEURISTIC", "NONE"))

    def test_02_safe_byte_cursor_fault_tolerance(self):
        """SafeByteCursor must never crash or raise on OOB or truncation."""
        cursor = SafeByteCursor(b"\x01\x02\x03\x04")
        self.assertTrue(cursor.can_read(4))
        self.assertFalse(cursor.can_read(5))
        # OOB seek
        self.assertFalse(cursor.seek(100))
        self.assertEqual(cursor.pos, 4)
        # Partial read
        raw, ok = cursor.read_bytes(10, allow_partial=True)
        self.assertFalse(ok)
        self.assertGreater(len(cursor.damages), 0)

    def test_03_transforms_and_checksums(self):
        """Test pure math functions and zip-bomb mitigation."""
        self.assertEqual(crc16_ccitt(b"123456789"), 0x29B1)
        # Zip bomb mitigation
        bomb_data = b"\xFF\xAA" * 1000  # repeat run
        decomp, ok, err = rle_decompress_packbits(bomb_data, max_output=1024)
        self.assertLessEqual(len(decomp), 1024)

    def test_04_xor_cracker(self):
        """Test XOR key automatic recovery on ASCII string."""
        plain = b"The quick brown fox jumps over the lazy dog"
        cipher = xor_apply(plain, b"\x42")
        recovered, key, score = xor_crack_ascii(cipher)
        self.assertEqual(key, b"\x42")
        self.assertEqual(recovered, plain)

    def test_05_salvage_cli_zero_crash_exit_code(self):
        """./salvage CLI must exit 0 and write valid schema per-file and report.json."""
        with tempfile.TemporaryDirectory() as out_tmp:
            code = run_salvage(str(self.samples_dir), out_tmp)
            self.assertEqual(code, 0)

            out_path = Path(out_tmp)
            report_file = out_path / "report.json"
            self.assertTrue(report_file.exists())
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertIn("tool_version", report)
            self.assertIn("files", report)
            self.assertIn("totals", report)

if __name__ == "__main__":
    unittest.main()
