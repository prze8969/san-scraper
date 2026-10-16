"""tools/hypothesize.py: Automated Reverse Engineering Companion.
Analyzes arbitrary binary samples to extract magic bytes, test endianness, brute-force XOR keys,
verify CRC16/32 algorithms, and output Markdown tables ready for FIELD-LOG.md.
"""

from __future__ import annotations
import sys
import struct
from pathlib import Path
from src.transforms import crc16_ccitt, crc16_arc, crc32_ieee, fletcher16, xor_crack_ascii, decode_dos_date

def analyze_sample(path: Path) -> dict:
    data = path.read_bytes()
    size = len(data)
    first_16_hex = data[:16].hex(" ") if size > 0 else "(empty)"
    ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in data[:32])

    # Endianness candidates
    u16_le = struct.unpack("<H", data[:2])[0] if size >= 2 else None
    u16_be = struct.unpack(">H", data[:2])[0] if size >= 2 else None
    u32_le = struct.unpack("<I", data[:4])[0] if size >= 4 else None

    # XOR cracking
    decrypted, best_key, xor_score = xor_crack_ascii(data[:min(512, size)])

    # CRCs
    c_ccitt = crc16_ccitt(data) if size > 0 else 0
    c_arc = crc16_arc(data) if size > 0 else 0
    c_32 = crc32_ieee(data) if size > 0 else 0

    return {
        "file": path.name,
        "size": size,
        "first_16_hex": first_16_hex,
        "ascii_preview": ascii_preview,
        "u16_le": f"0x{u16_le:04X}" if u16_le is not None else "N/A",
        "u16_be": f"0x{u16_be:04X}" if u16_be is not None else "N/A",
        "best_xor_key": best_key.hex(),
        "xor_ascii_score": f"{xor_score * 100:.1f}%",
        "crc16_ccitt": f"0x{c_ccitt:04X}",
        "crc16_arc": f"0x{c_arc:04X}",
        "crc32": f"0x{c_32:08X}",
    }

def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python tools/hypothesize.py <sample_dir>")
        sys.exit(0)

    target_dir = Path(sys.argv[1])
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"Error: Directory not found: {target_dir}")
        sys.exit(0)

    files = sorted([p for p in target_dir.iterdir() if p.is_file()])
    print(f"# Differential Analysis Report: {target_dir.name}\n")
    print(f"Total samples analyzed: {len(files)}\n")

    print("| File | Size | First 16 Bytes (Hex) | ASCII Preview | Best XOR Key | XOR ASCII % | CRC-16 CCITT |")
    print("|---|---|---|---|---|---|---|")
    for f in files:
        res = analyze_sample(f)
        print(f"| `{res['file']}` | {res['size']}B | `{res['first_16_hex']}` | `{res['ascii_preview']}` | `0x{res['best_xor_key']}` | {res['xor_ascii_score']} | `{res['crc16_ccitt']}` |")

if __name__ == "__main__":
    main()
