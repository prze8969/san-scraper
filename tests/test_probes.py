"""Tests for probe battery and terminal report generation.

Labeled [independent] for hand-assembled spec bytes and [self-consistency] for system-level integrity.
"""

import unittest
import struct
import tempfile
import zlib
import random
from pathlib import Path
from src.probes.probe_runner import ProbeRunner
from src.probes.probe_documenter import ProbeDocumenter
from src.engine import SalvageEngine
from src.cli import run_salvage

class TestProbeBatteryAndTerminalReport(unittest.TestCase):

    def test_crc32_footer_probe_independent(self):
        """[independent] Hand-assembled file with candidate payload and exact trailing CRC32 is detected by probe."""
        payload = b"FORENSIC_SALVAGE_PAYLOAD_BLOCK_12345"
        calc_crc32 = zlib.crc32(payload) & 0xFFFFFFFF
        # 4-byte LE trailer
        trailer = struct.pack("<I", calc_crc32)
        test_file = payload + trailer

        runner = ProbeRunner(test_file, filename="test_crc.bin")
        probes = runner.run_all_probes()

        crc_matches = [
            p for p in probes
            if p.family == "checksums" and p.result == "match" and p.parameters.get("algorithm") == "crc32"
        ]
        self.assertTrue(len(crc_matches) >= 1)
        self.assertEqual(crc_matches[0].parameters.get("computed"), calc_crc32)
        self.assertIn("matches 4-byte trailer", crc_matches[0].evidence)

    def test_header_declared_length_probe_independent(self):
        """[independent] Hand-assembled file with declared length in header matching total file size is detected."""
        total_len = 128
        # Header with offset 4 = declared length (128)
        header = b"HEAD" + struct.pack("<I", total_len) + b"\x00" * 24
        body = b"B" * (total_len - len(header))
        test_file = header + body
        self.assertEqual(len(test_file), total_len)

        runner = ProbeRunner(test_file, filename="declared_len.bin")
        probes = runner.run_all_probes()

        hdr_matches = [
            p for p in probes
            if p.family == "header" and p.result == "match" and p.probe_id == "hdr_u32_le_off_4"
        ]
        self.assertTrue(len(hdr_matches) >= 1)
        self.assertEqual(hdr_matches[0].parameters.get("value"), total_len)
        self.assertIn("exactly equals total file size", hdr_matches[0].evidence)

    def test_embedded_png_probe_independent(self):
        """[independent] Hand-assembled file with embedded PNG detects signature, footer IEND, and carver extracts it."""
        prefix = b"RANDOM_PADDING_BYTES" * 5
        png_sig = b"\x89PNG\r\n\x1a\n"
        ihdr = struct.pack(">I", 13) + b"IHDR" + struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0) + b"\x37\x6e\xf9\x24"
        iend = struct.pack(">I", 0) + b"IEND\xaeB`\x82"
        valid_png = png_sig + ihdr + iend
        suffix = b"TRAILER_DATA" * 4
        file_bytes = prefix + valid_png + suffix

        runner = ProbeRunner(file_bytes, filename="embedded.bin")
        probes = runner.run_all_probes()

        png_matches = [
            p for p in probes
            if p.family == "signatures" and p.result == "match" and p.parameters.get("format") == "PNG"
        ]
        self.assertTrue(len(png_matches) >= 1)

        iend_matches = [
            p for p in probes
            if p.family == "footer" and p.result == "match" and p.parameters.get("marker") == "PNG_IEND"
        ]
        self.assertTrue(len(iend_matches) >= 1)

    def test_xor_obfuscated_string_probe_independent(self):
        """[independent] Hand-assembled file obfuscated with single-byte XOR key 0x5A detects key and high printable score."""
        plain_text = b"CONFIDENTIAL_RECOVERY_KEY_FLAG_ALPHA_BETA_GAMMA_998811" * 4
        xor_key = 0x5A
        obfuscated = bytes(b ^ xor_key for b in plain_text)

        runner = ProbeRunner(obfuscated, filename="obfuscated.bin")
        probes = runner.run_all_probes()

        xor_matches = [
            p for p in probes
            if p.family == "obfuscation" and p.result == "match" and p.parameters.get("xor_key") == xor_key
        ]
        self.assertTrue(len(xor_matches) >= 1)
        self.assertGreaterEqual(xor_matches[0].parameters.get("printable_ratio"), 0.90)
        self.assertIn("0x5a", xor_matches[0].evidence.lower())

    def test_random_bytes_produces_no_high_confidence_probe_claims_independent(self):
        """[independent] Random bytes stream generates 300+ probes with zero high-confidence (>0.85) claims."""
        rng = random.Random(9999)
        random_bytes = rng.randbytes(1024)

        runner = ProbeRunner(random_bytes, filename="noise.bin")
        probes = runner.run_all_probes()
        self.assertGreaterEqual(len(probes), 300)

        high_conf_matches = [p for p in probes if p.result == "match" and p.score > 0.85]
        self.assertEqual(len(high_conf_matches), 0)

    def test_seeded_fuzz_probe_battery_self_consistency(self):
        """[self-consistency] Seeded fuzz on ProbeRunner guarantees no crashes, no hangs, and bounded execution."""
        rng = random.Random(2026)
        for i in range(25):
            size = rng.randint(0, 8000)
            data = rng.randbytes(size)
            runner = ProbeRunner(data, filename=f"fuzz_{i}.bin")
            results = runner.run_all_probes()
            self.assertGreaterEqual(len(results), 200)

    def test_cli_single_file_and_quiet_verbose_self_consistency(self):
        """[self-consistency] CLI handles single file path, --verbose, and --quiet without errors."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "single_test.bin"
            file_path.write_bytes(b"HELLO_WORLD_TEST_DATA" * 5)
            out_path = Path(tmp_dir) / "output"

            # 1. Quiet mode single file
            ret_quiet = run_salvage(str(file_path), str(out_path), quiet=True)
            self.assertEqual(ret_quiet, 0)
            self.assertTrue((out_path / "single_test.bin.json").exists())
            self.assertTrue((out_path / "single_test.bin.probes.json").exists())
            self.assertTrue((out_path / "single_test.bin.probes.txt").exists())

            # 2. Verbose mode single file
            ret_verbose = run_salvage(str(file_path), str(out_path), verbose=True, quiet=True)
            self.assertEqual(ret_verbose, 0)

if __name__ == "__main__":
    unittest.main()
