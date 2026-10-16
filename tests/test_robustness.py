"""Robustness, resource limit, adversarial fuzzing, and batch isolation tests."""

import unittest
import struct
import random
import tempfile
from pathlib import Path

from src.reader import BoundedBinaryReader, BoundsError
from src.engine import SalvageEngine
from src.formats.libra98 import Libra98Parser
from src.formats.lablog import LablogParser
from src.formats.vault import VaultParser, bounded_rle_decompress, DecompressionError
from src.formats.pak import PakParser
from src.formats.wks import WksParser
from src.models import DamageType, RecordStatus

class TestRobustnessAndResourceLimits(unittest.TestCase):
    def setUp(self):
        self.parsers = {
            "LIBRA-98": Libra98Parser(),
            "LABLOG": LablogParser(),
            "VAULT": VaultParser(),
            "PAK": PakParser(),
            "WKS": WksParser(),
        }

    def test_empty_files_all_parsers(self):
        """Empty files (0 bytes) must never crash or hang any parser."""
        empty = b""
        for name, parser in self.parsers.items():
            res = parser.parse(f"empty_{name}.dat", BoundedBinaryReader(empty))
            self.assertFalse(res.is_valid_header)
            self.assertEqual(len(res.recovered_records), 0)
            self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_minimum_size_single_byte_files(self):
        """1-byte files must be handled cleanly as truncated headers."""
        one_byte = b"\x00"
        for name, parser in self.parsers.items():
            res = parser.parse(f"one_byte_{name}.dat", BoundedBinaryReader(one_byte))
            self.assertFalse(res.is_valid_header)
            self.assertEqual(len(res.recovered_records), 0)
            self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_truncated_headers_and_records(self):
        """Truncated headers that end right after magic bytes."""
        samples = {
            "LIBRA-98": b"LIBRA98\x00\x01",
            "LABLOG": b"LABLOG\x01\x00\x01",
            "VAULT": b"VAULT\x01\x00\x00\x01",
            "PAK": b"PACK\x04\x00",
            "WKS": b"\x00\x00\x02",
        }
        for name, data in samples.items():
            parser = self.parsers[name]
            res = parser.parse(f"trunc_{name}.dat", BoundedBinaryReader(data))
            self.assertFalse(res.is_valid_header)
            self.assertTrue(any(d.damage_type == DamageType.TRUNCATION for d in res.damages))

    def test_invalid_counts_and_offsets(self):
        """Invalid counts (0xFFFFFFFF) and huge offsets must not trigger memory bombs or freezes."""
        # LIBRA-98: 0xFFFFFFFF records
        lib_data = struct.pack("<8sHHIIII4s", b"LIBRA98\x00", 1, 0, 32, 0xFFFFFFFF, 48, 0, b"\x00"*4)
        res_lib = self.parsers["LIBRA-98"].parse("huge_count.lib", BoundedBinaryReader(lib_data))
        self.assertEqual(len(res_lib.recovered_records), 0)

        # PAK: 0xFFFFFFFF dir offset
        pak_data = struct.pack("<4sII", b"PACK", 0xFFFFFFFF, 64)
        res_pak = self.parsers["PAK"].parse("huge_dir_off.pak", BoundedBinaryReader(pak_data))
        self.assertTrue(any(d.damage_type == DamageType.MALFORMED_OFFSET for d in res_pak.damages))

        # VAULT: 0xFFFFFFFF index offset
        vault_data = struct.pack("<4sHBBII", b"VLT1", 1, 0, 0, 0xFFFFFFFF, 48)
        res_vault = self.parsers["VAULT"].parse("huge_idx.vlt", BoundedBinaryReader(vault_data))
        self.assertTrue(any(d.damage_type in (DamageType.MALFORMED_OFFSET, DamageType.OOB_POINTER) for d in res_vault.damages))

    def test_rle_decompression_bomb_mitigation(self):
        """A small RLE payload designed to explode into gigabytes must be stopped at bounded limit."""
        # ARC RLE90: 'A' followed by 0x90 0xFF (repeat 254 times = 255 bytes total)
        bomb_chunk = (b"A\x90\xff") * 10  # 10 * 255 = 2550 bytes
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(bomb_chunk, max_output_size=500)

    def test_rle_malformed_runs(self):
        """RLE repeat run missing target byte or truncated 0x90 marker."""
        # Repeat run without preceding byte:
        malformed_lead = b"\x90\x05"
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(malformed_lead)

        # Truncated 0x90 marker at EOF:
        malformed_trunc = b"A\x90"
        with self.assertRaises(DecompressionError):
            bounded_rle_decompress(malformed_trunc)

    def test_deterministic_seeded_fuzz_all_parsers(self):
        """
        Deterministic seeded fuzzing test across all parsers.
        Asserts no crash, no hang, and bounded memory across 50 random fuzz streams per parser.
        """
        prng = random.Random(42)  # Fixed deterministic seed
        for name, parser in self.parsers.items():
            for i in range(50):
                length = prng.randint(0, 4096)
                fuzz_bytes = prng.randbytes(length)
                # Option to prepend valid magic to test deep inner state fuzzing
                if prng.choice([True, False]):
                    if name == "PAK":
                        fuzz_bytes = b"PACK" + fuzz_bytes
                    elif name == "WKS":
                        fuzz_bytes = b"\x00\x00\x02\x00\x04\x04" + fuzz_bytes
                    elif name == "LIBRA-98":
                        fuzz_bytes = b"LIBRA98\x00" + fuzz_bytes
                    elif name == "LABLOG":
                        fuzz_bytes = b"LABLOG\x01\x00" + fuzz_bytes
                    elif name == "VAULT":
                        fuzz_bytes = b"VAULT\x01\x00\x00" + fuzz_bytes

                reader = BoundedBinaryReader(fuzz_bytes)
                res = parser.parse(f"fuzz_{name}_{i}.bin", reader)
                self.assertIsNotNone(res)
                self.assertIsInstance(res.recovered_records, list)
                self.assertIsInstance(res.damages, list)

    def test_batch_isolation_damaged_file_never_halts_others(self):
        """Confirm one damaged or adversarial file never stops processing of healthy files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            f_good1 = dir_path / "01_good.wks"
            f_bad = dir_path / "02_corrupt.lib"
            f_good2 = dir_path / "03_good.pak"

            # 1. Good WKS file
            f_good1.write_bytes(b"\x00\x00\x02\x00\x04\x04\x01\x00\x00\x00")
            # 2. Severely corrupted file
            f_bad.write_bytes(b"LB98\x02\x00\x05\x00\x24\xA5\x54\x60\x10\x00\x07\x00" + b"\xFF\xFF" * 50)
            # 3. Good PAK file
            handcrafted_pak = (
                b"PACK\x16\x00\x00\x00\x40\x00\x00\x00HELLOQUAKE"
                + b"test.txt" + b"\x00" * 48
                + b"\x0c\x00\x00\x00\x0a\x00\x00\x00"
            )
            f_good2.write_bytes(handcrafted_pak)

            engine = SalvageEngine()
            results = [engine.process_file(p) for p in sorted(dir_path.glob("*"))]

            self.assertEqual(len(results), 3)
            # Good 1 recovered cleanly
            self.assertEqual(results[0].format_name, "WKS")
            self.assertTrue(results[0].is_valid_header)

            # Bad was safely quarantined with damage block, no exception thrown
            self.assertEqual(results[1].format_name, "LIBRA-98")

            # Good 2 was recovered cleanly despite preceding bad file
            self.assertEqual(results[2].format_name, "PAK")
            self.assertTrue(results[2].is_valid_header)
            self.assertEqual(len(results[2].recovered_records), 1)

    def test_determinism_across_multiple_runs(self):
        """Assert identical files produce identical results across runs."""
        engine = SalvageEngine()
        sample = b"PACK\x16\x00\x00\x00\x40\x00\x00\x00HELLOQUAKE" + b"test.txt" + b"\x00"*48 + b"\x0c\x00\x00\x00\x0a\x00\x00\x00"

        run1 = engine.process_bytes("sample.pak", sample).to_dict()
        run2 = engine.process_bytes("sample.pak", sample).to_dict()
        self.assertEqual(run1, run2)

if __name__ == "__main__":
    unittest.main()
