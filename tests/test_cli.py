"""End-to-end integration tests for CLI runner."""

import unittest
import tempfile
import json
import struct
from pathlib import Path
from src.cli import run_salvage
from tests.test_libra98 import build_synthetic_libra98
from tests.test_lablog import build_synthetic_lablog
from tests.test_vault import build_synthetic_vault
from tests.test_pak import build_synthetic_pak
from tests.test_wks import build_synthetic_wks

class TestCliIntegration(unittest.TestCase):
    def test_run_salvage_end_to_end(self):
        with tempfile.TemporaryDirectory() as tmp_in_dir, tempfile.TemporaryDirectory() as tmp_out_dir:
            in_path = Path(tmp_in_dir)
            out_path = Path(tmp_out_dir)

            # 1. Synthetic LIBRA-98 file
            records = [(1, 100, 0, 999, "CLI Test")]
            (in_path / "sample.lib").write_bytes(build_synthetic_libra98(records))

            # 2. Synthetic LABLOG file
            blocks = [(0, 1, 0, 100, b"Log Entry Alpha")]
            (in_path / "sample.lab").write_bytes(build_synthetic_lablog(blocks))

            # 3. Synthetic VAULT file
            vault_entries = [{"id": 1, "name": "vault_f.txt", "data": b"Vault Data", "rle": False}]
            (in_path / "sample.vlt").write_bytes(build_synthetic_vault(vault_entries))

            # 4. Synthetic Quake PAK file
            pak_files = [("pak_f.txt", b"Quake PAK payload")]
            (in_path / "sample.pak").write_bytes(build_synthetic_pak(pak_files))

            # 5. Synthetic Lotus WKS file
            wks_recs = [(0x0000, struct.pack("<H", 0x0404)), (0x0001, b"")]
            (in_path / "sample.wks").write_bytes(build_synthetic_wks(wks_recs))

            # 6. Empty file
            (in_path / "empty.bin").write_bytes(b"")

            # 7. Unknown file
            (in_path / "mystery.dat").write_bytes(b"\xFE\xED\xFA\xCE")

            exit_code = run_salvage(str(in_path), str(out_path))
            self.assertEqual(exit_code, 0)

            # Verify output files
            for fname in ["sample.lib", "sample.lab", "sample.vlt", "sample.pak", "sample.wks", "empty.bin", "mystery.dat"]:
                self.assertTrue((out_path / f"{fname}.json").exists())
            self.assertTrue((out_path / "report.json").exists())

            # Verify report.json content
            with open(out_path / "report.json", "r", encoding="utf-8") as f:
                report = json.load(f)

            self.assertEqual(report["summary"]["total_files_processed"], 7)
            self.assertIn("LIBRA-98", report["summary"]["formats"])
            self.assertIn("LABLOG", report["summary"]["formats"])
            self.assertIn("VAULT", report["summary"]["formats"])
            self.assertIn("PAK", report["summary"]["formats"])
            self.assertIn("WKS", report["summary"]["formats"])
            self.assertIn("EMPTY", report["summary"]["formats"])
            self.assertIn("UNKNOWN", report["summary"]["formats"])

if __name__ == "__main__":
    unittest.main()
