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

    # 9. PNG buried in junk bytes (for carving demonstration)
    junk_prefix = b"JUNK_BYTES_PADDING_START_" * 8
    ihdr_payload = struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0)
    ihdr_chunk = struct.pack(">I", len(ihdr_payload)) + b"IHDR" + ihdr_payload + b"\xc9\x04\xe1\x70"
    iend_chunk = struct.pack(">I", 0) + b"IEND\xaeB`\x82"
    buried_png = b"\x89PNG\r\n\x1a\n" + ihdr_chunk + iend_chunk
    junk_suffix = b"_JUNK_BYTES_PADDING_END" * 4
    (target_dir / "09_buried_png.bin").write_bytes(junk_prefix + buried_png + junk_suffix)

    # 10. Record file with unknown format (fixed 32-byte stride for heuristic candidate-record recovery)
    rec_bytes = []
    for i in range(16):
        rec_bytes.append(b"EVNT" + struct.pack("<II", 1000 + i, 1718000000 + i * 10) + b"STATUS_OK\x00" * 2)
    (target_dir / "10_unknown_records.dat").write_bytes(b"".join(rec_bytes))

    # 11. Header-damaged PAK file (PAK with corrupt/wrapped prefix)
    pak_corrupt_files = [
        ("config.cfg", b"bind 'MOUSE1' '+attack'\n"),
        ("autoexec.cfg", b"echo 'Header-damaged PAK recovered successfully!'\n"),
    ]
    raw_pak = build_synthetic_pak(pak_corrupt_files)
    # Corrupt the magic by prepending 64 bytes of junk (magic is now at offset 64)
    (target_dir / "11_header_damaged.pak").write_bytes(b"CORRUPTED_PREFIX_WRAPPER_METADATA_HEADER_BLOB_PADDING_TO_OFFSET_64"[:64] + raw_pak)

    # 12. Valid Doom WAD (documented IWAD layout)
    l1 = b"SECTOR_MAP_DATA_DEMO"
    l2 = b""  # F_START marker
    l3 = b"TEXTURE1_DESCRIPTOR_TABLE"
    p1 = 12
    p2 = p1 + len(l1)
    p3 = p2 + len(l2)
    dir_p = p3 + len(l3)
    wad_dir = (
        struct.pack("<II8s", p1, len(l1), b"MAP01\x00\x00\x00") +
        struct.pack("<II8s", p2, len(l2), b"F_START\x00") +
        struct.pack("<II8s", p3, len(l3), b"TEXTURE1")
    )
    wad_hdr = struct.pack("<4sII", b"IWAD", 3, dir_p)
    (target_dir / "12_valid.wad").write_bytes(wad_hdr + l1 + l2 + l3 + wad_dir)

    # 13. Valid ZIP Archive (documented PKWARE layout with stored + deflate files)
    zf1_name = b"notes.txt"
    zf1_data = b"Salvaged notes from documented ZIP parser!"
    zf1_crc = zlib.crc32(zf1_data)
    zf1_hdr = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 0, 0, 0, zf1_crc, len(zf1_data), len(zf1_data), len(zf1_name), 0) + zf1_name + zf1_data

    zf2_name = b"compressed/data.log"
    zf2_data = b"LOG_ENTRY_REPEAT_STRING_" * 20
    zf2_comp = zlib.compress(zf2_data)[2:-4]
    zf2_crc = zlib.crc32(zf2_data)
    zf2_hdr = struct.pack("<4sHHHHHIIIHH", b"PK\x03\x04", 20, 0, 8, 0, 0, zf2_crc, len(zf2_comp), len(zf2_data), len(zf2_name), 0) + zf2_name + zf2_comp
    (target_dir / "13_valid.zip").write_bytes(zf1_hdr + zf2_hdr)

    # 14. Valid GZIP stream (RFC 1952 layout)
    import gzip
    gz_payload = b"RFC 1952 GZIP compressed stream rescued with validated CRC-32."
    (target_dir / "14_valid.gz").write_bytes(gzip.compress(gz_payload))

    print(f"Successfully created 14 demo fixtures in {target_dir}")

if __name__ == "__main__":
    create_demo_fixtures(Path("demo/input"))
