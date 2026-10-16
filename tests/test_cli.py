"""End-to-end integration tests for CLI runner."""

import unittest
import tempfile
import json
import shutil
from pathlib import Path
from src.cli import run_salvage

class TestCliIntegration(unittest.TestCase):
    def test_run_salvage_end_to_end(self):
        samples_dir = Path("Genesis_Track3_PS2_Sample_Files-main/samples")
        if not samples_dir.exists():
            samples_dir = Path(__file__).resolve().parent.parent / "Genesis_Track3_PS2_Sample_Files-main" / "samples"
        if not samples_dir.exists():
            raise unittest.SkipTest("Samples directory not found")

        with tempfile.TemporaryDirectory() as tmp_in_dir, tempfile.TemporaryDirectory() as tmp_out_dir:
            in_path = Path(tmp_in_dir)
            out_path = Path(tmp_out_dir)

            test_files = [
                "s01.dat",      # LIBRA-98
                "s05.dat",      # LABLOG
                "s08.dat",      # VAULT
                "s11.wks",      # WKS
                "s14.wpd",      # WPD
                "s16.bravo",    # BRAVO
                "s18.cvt",      # CVT
                "s20.000",      # EBCDIC-DUMP
                "s23.wad",      # WAD
                "s24.pak",      # PAK
                "s26_empty.dat", # UNKNOWN (empty)
                "s25_random.bin" # UNKNOWN (random)
            ]

            for fname in test_files:
                shutil.copy(samples_dir / fname, in_path / fname)

            exit_code = run_salvage(str(in_path), str(out_path))
            self.assertEqual(exit_code, 0)

            # Verify every file has an output JSON
            for fname in test_files:
                out_json = out_path / f"{fname}.json"
                self.assertTrue(out_json.exists(), f"Output JSON {out_json} missing")
                content = json.loads(out_json.read_text(encoding="utf-8"))
                self.assertIn("source_file", content)
                self.assertIn("format", content)
                self.assertIn("status", content)

            # Verify report.json
            report_file = out_path / "report.json"
            self.assertTrue(report_file.exists())
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["total_files_processed"], len(test_files))
            self.assertIn("LIBRA-98", report["summary"]["formats"])
            self.assertIn("LABLOG", report["summary"]["formats"])
            self.assertIn("VAULT", report["summary"]["formats"])
            self.assertIn("WKS", report["summary"]["formats"])
            self.assertIn("WPD", report["summary"]["formats"])
            self.assertIn("BRAVO", report["summary"]["formats"])
            self.assertIn("CVT", report["summary"]["formats"])
            self.assertIn("EBCDIC-DUMP", report["summary"]["formats"])
            self.assertIn("WAD", report["summary"]["formats"])
            self.assertIn("PAK", report["summary"]["formats"])
            self.assertIn("UNKNOWN", report["summary"]["formats"])
