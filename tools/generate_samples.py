"""tools/generate_samples.py: Generates golden & corrupted binary test vectors for all 10 formats."""

from __future__ import annotations
import sys
import struct
import zlib
from pathlib import Path

def generate_samples(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. LIBRA-98 Clean
    # Header: LB98 (4B), version 2 (2B), count 1 (2B), dos_date 0x2543 (2B), dos_time 0x5A8B (2B), data_offset 16 (2B), branch 576 (2B)
    hdr_libra = struct.pack("<4sHHHHHH", b"LB98", 2, 1, 0x2543, 0x5A8B, 16, 576)
    # Record: sync 0xA5, len 32, flags 0x01 (checked out)
    # payload: rec_id (u32=1001), title_len (1B), title, author_len (1B), author, year_raw (u16=397 -> 1897), price (u16=499), copies (1B=3), isbn (10B), due_date (u16=0x2553)
    rec_payload = struct.pack("<IB", 1001, 7) + b"Dracula" + struct.pack("<B", 11) + b"Bram Stoker" + struct.pack("<HHB10sH", 397, 499, 3, b"4010278714", 0x2553)
    rec_libra = b"\xA5" + struct.pack("<BB", len(rec_payload) + 1, 0x01) + rec_payload
    (out_dir / "gen_libra_clean.dat").write_bytes(hdr_libra + rec_libra)

    # 2. LIBRA-98 Corrupted (Truncated record)
    (out_dir / "gen_libra_truncated.dat").write_bytes(hdr_libra + rec_libra[:15])

    # 3. LABLOG Clean
    hdr_lablog = b"LLOG" + bytes([1, 2]) + struct.pack("<H", 50) + b"TEST LOGGER\x00\x00\x00\x00\x00" + struct.pack("<IH", 87600000, 1) + b"\x00" * 6
    # 2 channels: 12B each
    ch1 = b"mV\x00\x00" + struct.pack("<ff", 1.0, 0.0)
    ch2 = b"ppm\x00" + struct.pack("<ff", 0.5, 10.0)
    hdr_crc = b"\x00\x00"
    # Block: sync 0xB1, type 1 (DATA), len 11, crc16
    blk_body = struct.pack("<HB", 0, 1) + struct.pack("<hh", 100, 200)
    blk_crc = b"\x00\x00"
    blk = b"\xB1\x01" + struct.pack("<H", len(blk_body)) + blk_body + blk_crc
    (out_dir / "gen_lablog_clean.dat").write_bytes(hdr_lablog + ch1 + ch2 + hdr_crc + blk)

    # 4. LABLOG Resync recovery (corrupted noise followed by 0xB1 sync block)
    noise = b"RANDOM_CORRUPTION_NOISE_BYTES_HERE"
    (out_dir / "gen_lablog_resync.dat").write_bytes(hdr_lablog + ch1 + ch2 + hdr_crc + noise + blk)

    # 5. VAULT Clean
    hdr_vault = b"VLT1" + struct.pack("<HHHI", 1, 0, 0, 16)
    # Entry: blob at offset 16, stored_sz 14, decoded_sz 10, name at index
    # Single text file: "hello world"
    txt_payload = b"\x00\x00\x00\x00hello world"
    entry_desc = struct.pack("<HBBIIHH", 101, 1, 0, 0, 16, len(txt_payload), 11)
    name_tbl = struct.pack("<B", 8) + b"test.txt"
    (out_dir / "gen_vault_clean.dat").write_bytes(hdr_vault + txt_payload + name_tbl + entry_desc)

    # 6. WAD
    hdr_wad = b"PWAD" + struct.pack("<ii", 1, 20)
    lump_data = b"DEMO_LUMP_DATA"
    lump_dir = struct.pack("<ii8s", 12, len(lump_data), b"MAP01\x00\x00\x00")
    (out_dir / "gen_wad.wad").write_bytes(hdr_wad + lump_data + lump_dir)

    # 7. PAK
    hdr_pak = b"PACK" + struct.pack("<ii", 20, 64)
    file_data = b"echo quake"
    pak_entry = b"default.cfg".ljust(56, b"\x00") + struct.pack("<ii", 12, len(file_data))
    (out_dir / "gen_pak.pak").write_bytes(hdr_pak + file_data + pak_entry)

    # 8. WKS
    bof = b"\x00\x00\x02\x00\x04\x04"
    cell_int = b"\x0D\x00\x07\x00" + bytes([0]) + struct.pack("<HHh", 0, 0, 42)
    eof = b"\x01\x00\x00\x00"
    (out_dir / "gen_wks.wks").write_bytes(bof + cell_int + eof)

    # 9. 0-byte file
    (out_dir / "gen_empty.dat").write_bytes(b"")

    # 10. Random garbage file
    (out_dir / "gen_garbage.bin").write_bytes(b"\xDE\xAD\xBE\xEF" * 64)

    print(f"Synthesized 10 sample vectors in {out_dir}")

def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample_data")
    generate_samples(target)

if __name__ == "__main__":
    main()
