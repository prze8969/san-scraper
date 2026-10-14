"""Script to generate realistic synthetic test fixtures for judge demo."""

import os
import struct
import zlib
from pathlib import Path

from tests.test_pak import build_synthetic_pak
from tests.test_wks import build_synthetic_wks
from tests.test_libra98 import build_synthetic_libra98
from tests.test_lablog import build_synthetic_lablog
from tests.test_vault import build_synthetic_vault

def create_demo_fixtures(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Valid LIBRA-98 (initial validation gate format)
    libra_records = [
        (101, 1718000000, 1, 1500, "Sensor_Alpha_OK"),
        (102, 1718000060, 1, 1520, "Sensor_Beta_OK"),
        (103, 1718000120, 0, 9999, "Calibration_Mark"),
    ]
    (target_dir / "01_valid.lib").write_bytes(build_synthetic_libra98(libra_records))

    # 2. Valid LABLOG (block-based telemetry journal)
    lablog_blocks = [
        (0, 1, 0, 1718000010, b"System boot sequence initiated."),
        (1, 1, 0, 1718000020, b"Core temperature stabilized at 38.5C."),
        (2, 2, 0, 1718000030, b"Notice: routine health ping received."),
    ]
    (target_dir / "02_valid.lab").write_bytes(build_synthetic_lablog(lablog_blocks))

    # 3. Valid VAULT (archive format with PackBits RLE & XOR encryption)
    vault_entries = [
        {"id": 1, "name": "manifest.txt", "data": b"VAULT demo manifest v1.0", "rle": False, "xor_key": 0},
        {"id": 2, "name": "compressed_table.dat", "data": b"AAAAABBBBBCCCCCDDDDD" * 4, "rle": True, "xor_key": 0},
        {"id": 3, "name": "secured_token.key", "data": b"SECRET_AUTHENTICATION_KEY_9921", "rle": False, "xor_key": 0x5A},
    ]
    (target_dir / "03_valid.vlt").write_bytes(build_synthetic_vault(vault_entries))

    # 4. Valid Quake PAK (game archive format)
    pak_files = [
        ("progs.dat", b"\x01\x02\x03\x04" * 16),
        ("maps/e1m1.bsp", b"QUAKE_BSP_HEADER_CHUNK_DATA"),
        ("sound/player/jump.wav", b"RIFF_SAMPLE_WAVE_DATA"),
    ]
    (target_dir / "04_valid.pak").write_bytes(build_synthetic_pak(pak_files))

    # 5. Valid Lotus 1-2-3 Release 1A .WKS (legacy spreadsheet format)
    bof_payload = struct.pack("<H", 0x0404)
    blank_payload = struct.pack("<BHH", 0, 0, 0)
    int_payload = struct.pack("<BHHh", 0, 1, 2, 42)
    num_payload = struct.pack("<BHHd", 0, 2, 2, 98.6)
    lbl_payload = struct.pack("<BHHB", 0, 3, 3, ord("'")) + b"REVENUE_Q1\x00"
    formula_payload = struct.pack("<BHHd", 0, 4, 4, 140.6)
    wks_records = [
        (0x0000, bof_payload),
        (0x000C, blank_payload),
        (0x000D, int_payload),
        (0x000E, num_payload),
        (0x000F, lbl_payload),
        (0x0010, formula_payload),
        (0x0001, b""),
    ]
    (target_dir / "05_valid.wks").write_bytes(build_synthetic_wks(wks_records))

    # 6. Truncated file (PAK file with directory cut in half)
    pak_trunc_files = [
        ("textures/wall.wal", b"WALL_TEXTURE_DATA_CHUNK"),
        ("scripts/autoexec.cfg", b"echo 'Config loaded'"),
    ]
    (target_dir / "06_truncated.pak").write_bytes(build_synthetic_pak(pak_trunc_files, truncate_bytes=40))

    # 7. File with corrupted checksum/block (LABLOG with bad CRC in middle block)
    lablog_damaged_blocks = [
        (0, 1, 0, 1718000100, b"Valid block 0 before corruption."),
        (1, 1, 0, 1718000110, b"Damaged block with bad CRC payload."),
        (2, 1, 0, 1718000120, b"Valid block 2 cleanly recovered after bad block!"),
    ]
    (target_dir / "07_corrupted_block.lab").write_bytes(
        build_synthetic_lablog(lablog_damaged_blocks, corrupt_block_crc_idx=1)
    )

    # 8. Unknown / random bytes file
    (target_dir / "08_unknown.bin").write_bytes(
        b"\x7fELF_FAKE_BINARY_STREAM_DOES_NOT_MATCH_ANY_SUPPORTED_MAGIC_BYTES_12345"
    )

    print(f"Successfully created 8 demo fixtures in {target_dir}")

if __name__ == "__main__":
    create_demo_fixtures(Path("demo/input"))
