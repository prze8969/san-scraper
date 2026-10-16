"""Tests for format detection, pipeline engine, and damage reporting."""

import unittest
from pathlib import Path
import tempfile
import json
from src.detector import FormatDetector
from src.engine import SalvageEngine
from src.reporter import Reporter
from src.models import DamageType

class TestEngineAndReporter(unittest.TestCase):
    def test_format_detector(self):
        self.assertEqual(FormatDetector.detect(b"").format_name, "EMPTY")
        self.assertEqual(FormatDetector.detect(b"LB98\x02\x00\x01\x00\x00\x00\x00\x00\x10\x00\x01\x00").format_name, "LIBRA-98")
        self.assertEqual(FormatDetector.detect(b"LLOG\x01\x02").format_name, "LABLOG")
        self.assertEqual(FormatDetector.detect(b"PACK\x00\x00\x00\x00").format_name, "PAK")
        self.assertEqual(FormatDetector.detect(b"RANDOM_BYTES").format_name, "UNKNOWN")

    def test_engine_unknown_and_empty_file(self):
        engine = SalvageEngine()
        
        # Test empty
        res_empty = engine.process_bytes("empty.bin", b"")
        self.assertEqual(res_empty.format_name, "EMPTY")
        self.assertEqual(len(res_empty.damages), 1)
        self.assertEqual(res_empty.damages[0].damage_type, DamageType.TRUNCATION)

        # Test unknown
        res_unknown = engine.process_bytes("random.bin", b"\x99\x88\x77\x66")
        self.assertEqual(res_unknown.format_name, "UNKNOWN")
        self.assertEqual(res_unknown.damages[0].damage_type, DamageType.UNKNOWN_SIGNATURE)

    def test_reporter_file_and_run_summary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            reporter = Reporter(tmpdir)
            engine = SalvageEngine()

            res1 = engine.process_bytes("test1.bin", b"")
            res2 = engine.process_bytes("test2.bin", b"\xFF\xFE\xFD")

            reporter.add_result(res1)
            reporter.write_file_result(res1)
            reporter.add_result(res2)
            reporter.write_file_result(res2)

            report_file = reporter.write_run_report()
            self.assertTrue(Path(report_file).exists())

            with open(report_file, "r", encoding="utf-8") as f:
                report = json.load(f)

            self.assertEqual(len(report["files"]), 2)
            self.assertEqual(report["totals"]["unrecognized"], 2)

if __name__ == "__main__":
    unittest.main()
