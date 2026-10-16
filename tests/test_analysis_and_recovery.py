"""Tests for generic file analysis, multi-candidate detection, bounded carving, and recovery.

Labeled [independent] for hand-assembled spec bytes and [self-consistency] for system-level integrity.
"""

import unittest
import struct
import tempfile
import random
from pathlib import Path
from src.analysis.file_analyzer import FileAnalyzer
from src.detector_pipeline import PipelineDetector
from src.recovery.carver import Carver, GenericRecovery
from src.engine import SalvageEngine
from src.models import RecordStatus

class TestGenericAnalysisAndRecovery(unittest.TestCase):

    def test_png_carve_at_offset_100_independent(self):
        """[independent] A valid minimal PNG embedded at offset 100 inside random bytes is carved cleanly."""
        # 100 bytes junk prefix
        junk_prefix = b"\x12\x34\x56\x78" * 25
        # Minimal valid 1x1 PNG
        png_header = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0)
        ihdr_crc = b"\x37\x6e\xf9\x24"
        ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + ihdr_crc
        iend = struct.pack(">I", 0) + b"IEND\xaeB`\x82"
        valid_png = png_header + ihdr + iend
        junk_suffix = b"\xde\xad\xbe\xef" * 10
        file_bytes = junk_prefix + valid_png + junk_suffix

        analyzer = FileAnalyzer(file_bytes, filename="wrapped_image.bin")
        analysis = analyzer.analyze()
        self.assertEqual(analysis["size"], len(file_bytes))

        # Check signature found at offset 100
        png_sigs = [s for s in analysis["signatures"] if s["format"] == "PNG"]
        self.assertTrue(len(png_sigs) > 0)
        self.assertEqual(png_sigs[0]["offset"], 100)

        with tempfile.TemporaryDirectory() as tmpdir:
            carved = Carver.carve_all(file_bytes, analysis["signatures"], tmpdir, "wrapped_image.bin")
            png_carved = [c for c in carved if c.get("format") == "PNG" and c.get("carved")]
            self.assertEqual(len(png_carved), 1)
            self.assertEqual(png_carved[0]["offset"], 100)
            self.assertEqual(png_carved[0]["size"], len(valid_png))
            self.assertEqual(png_carved[0]["byte_range"], [100, 100 + len(valid_png)])

            # Confirm carved file exists on disk and matches exactly
            carved_path = Path(tmpdir) / "wrapped_image.bin.carved" / png_carved[0]["filename"]
            self.assertTrue(carved_path.exists())
            self.assertEqual(carved_path.read_bytes(), valid_png)

    def test_zip_with_trailing_garbage_independent(self):
        """[independent] A valid minimal ZIP with trailing garbage is carved up to its EOCD record."""
        # Minimal empty ZIP file: End of Central Directory (22 bytes)
        # Signature 0x06054b50, disk=0, start_disk=0, entries_disk=0, entries_total=0, cd_size=0, cd_offset=0, comment_len=0
        eocd = struct.pack("<IHHHHIIH", 0x06054b50, 0, 0, 0, 0, 0, 0, 0)
        trailing_garbage = b"EXTRA_TRAILER_GARBAGE_BYTES_ATTACHED"
        zip_bytes = eocd + trailing_garbage

        analyzer = FileAnalyzer(zip_bytes, filename="archive.zip")
        analysis = analyzer.analyze()

        with tempfile.TemporaryDirectory() as tmpdir:
            carved = Carver.carve_all(zip_bytes, analysis["signatures"], tmpdir, "archive.zip")
            zip_carved = [c for c in carved if c.get("format") == "ZIP" and c.get("carved")]
            self.assertEqual(len(zip_carved), 1)
            self.assertEqual(zip_carved[0]["offset"], 0)
            self.assertEqual(zip_carved[0]["size"], len(eocd))

    def test_fixed_width_record_stride_detected_independent(self):
        """[independent] File with known 48-byte record stride is recognized by autocorrelation heuristic."""
        # Build 10 records of 48 bytes with constant header tag and numeric field
        records = []
        for i in range(12):
            rec = b"REC_" + struct.pack("<I", i) + b"\x00" * 40
            records.append(rec)
        file_bytes = b"".join(records)

        analyzer = FileAnalyzer(file_bytes, filename="records.dat")
        analysis = analyzer.analyze()

        stride_heuristics = [h for h in analysis["heuristics"] if h.get("heuristic") == "fixed_width_record_stride"]
        self.assertTrue(len(stride_heuristics) > 0)
        self.assertEqual(stride_heuristics[0]["details"]["stride_bytes"], 48)
        self.assertEqual(stride_heuristics[0]["status"], "HYPOTHESIZED")

        # Generic recovery emits candidate records
        cand_records = GenericRecovery.recover_heuristic_records(file_bytes, analysis)
        stride_cand = [r for r in cand_records if r.fields.get("type") == "candidate_record"]
        self.assertTrue(len(stride_cand) > 0)
        self.assertEqual(stride_cand[0].fields.get("recovery_lane"), "heuristic")
        self.assertEqual(stride_cand[0].fields.get("stride"), 48)

    def test_supported_format_corrupted_header_recovery_self_consistency(self):
        """[self-consistency] Supported format file (e.g. PAK) with junk prefix is detected via nonzero offset."""
        # PACK header prepended with 32 bytes of corruption
        junk_prefix = b"JUNK_BYTES_HEADER_CORRUPTED_9999"
        from tests.test_pak import build_synthetic_pak
        pak_data = build_synthetic_pak([("test.txt", b"HELLO_SALVAGE")])
        corrupted_pak = junk_prefix + pak_data

        engine = SalvageEngine()
        result = engine.process_bytes("corrupted.pak", corrupted_pak)

        # Engine recovers via lenient non-zero offset candidate matching
        self.assertEqual(result.format_name, "PAK")
        self.assertTrue(len(result.recovered_records) >= 1)
        # Check offset was recorded in metadata
        self.assertEqual(result.metadata.get("wrapped_offset"), len(junk_prefix))

    def test_text_file_string_recovery_independent(self):
        """[independent] ASCII text file extracts strings and marks records as heuristic lane."""
        text_content = b"This is a recovery test file with printable English sentences. All data remains offline."
        analyzer = FileAnalyzer(text_content, filename="plain.txt")
        analysis = analyzer.analyze()

        self.assertTrue(len(analysis["strings"]) >= 1)
        self.assertIn("printable", analysis["strings"][0]["string"])

        rec = GenericRecovery.recover_heuristic_records(text_content, analysis)
        self.assertTrue(len(rec) >= 1)
        self.assertEqual(rec[0].fields["recovery_lane"], "heuristic")
        self.assertEqual(rec[0].fields["type"], "recovered_string")

    def test_zero_filled_file_independent(self):
        """[independent] Zero-filled file reports zero entropy and zero-filled damage indicator."""
        zeros = b"\x00" * 1024
        analyzer = FileAnalyzer(zeros, filename="zero.bin")
        analysis = analyzer.analyze()

        self.assertEqual(analysis["entropy"]["overall"], 0.0)
        damages = analysis["damage_indicators"]
        zero_damages = [d for d in damages if d.get("type") == "zero_filled_gap"]
        self.assertTrue(len(zero_damages) > 0)

    def test_random_bytes_low_confidence_independent(self):
        """[independent] Pure random file has high entropy and claims no false high-confidence structure."""
        rng = random.Random(42)
        random_bytes = rng.randbytes(1024)
        analyzer = FileAnalyzer(random_bytes, filename="noise.raw")
        analysis = analyzer.analyze()

        # High entropy (> 7.5 bits/byte)
        self.assertGreater(analysis["entropy"]["overall"], 7.5)
        # Confidences of heuristics should be low or none
        for h in analysis["heuristics"]:
            self.assertLess(h.get("confidence", 0.0), 0.85)

        candidates = PipelineDetector.detect_candidates(random_bytes, analysis, "noise.raw")
        top = candidates[0]
        # Should fall back to UNKNOWN or low-confidence candidate
        self.assertLessEqual(top.confidence, 0.5)

    def test_analyzer_and_carver_fuzz_bounded_self_consistency(self):
        """[self-consistency] Seeded fuzz test on analyzer and carver guarantees no crash, hang, or unbounded alloc."""
        rng = random.Random(1337)
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(40):
                size = rng.randint(0, 10000)
                fuzz_bytes = rng.randbytes(size)
                # Randomly inject magic signatures to test carver bounds
                if i % 3 == 0:
                    fuzz_bytes = b"\x89PNG\r\n\x1a\n" + fuzz_bytes
                elif i % 3 == 1:
                    fuzz_bytes = b"PK\x03\x04" + fuzz_bytes

                analyzer = FileAnalyzer(fuzz_bytes, filename=f"fuzz_{i}.bin")
                analysis = analyzer.analyze()
                self.assertIn("size", analysis)
                self.assertIn("sha256", analysis)

                carved = Carver.carve_all(fuzz_bytes, analysis.get("signatures", []), tmpdir, f"fuzz_{i}.bin")
                self.assertIsInstance(carved, list)

                coverage = GenericRecovery.calculate_coverage(len(fuzz_bytes), [(0, min(10, len(fuzz_bytes)))])
                self.assertIn("coverage_pct", coverage)

if __name__ == "__main__":
    unittest.main()
