"""Official Participant Kit validation tests.
Verifies zero regression against all 7 golden reference expected outputs
and validates non-crashing execution across all 30 sample files.
"""

import unittest
import json
import tempfile
from pathlib import Path
from src.cli import run_salvage
from src.engine import SalvageEngine

class TestParticipantKit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.samples_dir = Path("Genesis_Track3_PS2_Sample_Files-main/samples")
        cls.expected_dir = Path("Genesis_Track3_PS2_Sample_Files-main/expected_outputs")
        if not cls.samples_dir.exists():
            base = Path(__file__).resolve().parent.parent / "Genesis_Track3_PS2_Sample_Files-main"
            cls.samples_dir = base / "samples"
            cls.expected_dir = base / "expected_outputs"
        if not cls.samples_dir.exists():
            raise unittest.SkipTest("Participant kit samples not found")
        cls.engine = SalvageEngine()

    def test_golden_references_100_percent_match(self):
        """All 7 reference outputs in expected_outputs must match 100%."""
        for exp_path in sorted(self.expected_dir.glob("*.json")):
            fname = exp_path.stem  # e.g. s01.dat from s01.dat.json
            sample_file = self.samples_dir / fname
            self.assertTrue(sample_file.exists(), f"Sample file {sample_file} not found")

            exp = json.loads(exp_path.read_text(encoding="utf-8"))
            res = self.engine.process_file(sample_file).to_dict()

            # 1. Format match
            self.assertEqual(res.get("format"), exp.get("format"), f"Format mismatch on {fname}")

            # 2. Status match
            self.assertEqual(res.get("status"), exp.get("status"), f"Status mismatch on {fname}")

            # 3. Metadata match
            for k, v in exp.get("metadata", {}).items():
                self.assertEqual(
                    res.get("metadata", {}).get(k),
                    v,
                    f"Metadata key '{k}' mismatch on {fname}: {res.get('metadata', {}).get(k)} != {v}"
                )

            # 4. Records match
            exp_recs = exp.get("records", [])
            res_recs = res.get("records", [])
            self.assertEqual(len(res_recs), len(exp_recs), f"Record count mismatch on {fname}")

            for i, (r, e) in enumerate(zip(res_recs, exp_recs)):
                for rk, rv in e.items():
                    self.assertEqual(
                        r.get(rk),
                        rv,
                        f"Record {i} field '{rk}' mismatch on {fname}: {r.get(rk)} != {rv}"
                    )

    def test_all_30_samples_execution_and_schema(self):
        """Every file in samples must process cleanly and produce schema-compliant JSON."""
        with tempfile.TemporaryDirectory() as tmp_out:
            exit_code = run_salvage(str(self.samples_dir), tmp_out)
            self.assertEqual(exit_code, 0, "CLI runner must exit 0")

            out_path = Path(tmp_out)
            report_file = out_path / "report.json"
            self.assertTrue(report_file.exists(), "report.json must be emitted")

            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertIn("tool_version", report)
            self.assertIn("files", report)
            self.assertIn("totals", report)

            # Check that every sample file has a corresponding JSON
            for sample in self.samples_dir.iterdir():
                if sample.is_file():
                    target_json = out_path / f"{sample.name}.json"
                    self.assertTrue(target_json.exists(), f"Output JSON {target_json} missing")

                    content = json.loads(target_json.read_text(encoding="utf-8"))
                    self.assertIn("source_file", content)
                    self.assertIn("format", content)
                    self.assertIn("status", content)
                    self.assertIn("metadata", content)
                    self.assertIn("records", content)
                    self.assertIn("damage", content)
                    self.assertIn(content["status"], ["ok", "partial", "unsupported", "unrecognized", "failed"])
