import sys
import struct
from pathlib import Path

# Ensure project root is first in sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.test_pak import build_real_pak
from tests.test_wks import build_real_wks
from tests.test_libra98 import build_real_libra98
from tests.test_lablog import build_real_lablog
from tests.test_vault import build_real_vault

def create_demo_fixtures(target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)

    # 1. Valid LIBRA-98 (municipal library circulation format)
    libra_records = [
        {"id": 101, "title": "Structure and Interpretation of Computer Programs", "author": "Abelson & Sussman", "year": 1996, "price_cents": 5500, "copies": 4, "isbn": "0262011530", "flags": 0},
        {"id": 102, "title": "Design Patterns", "author": "Gang of Four", "year": 1994, "price_cents": 4999, "copies": 1, "isbn": "0201633612", "flags": 1},
    ]
    (target_dir / "01_valid.lib").write_bytes(build_real_libra98(libra_records))

    # 2. Valid LABLOG (sensor telemetry stream)
    channels = [("mV", 0.1, 0.0), ("degC", 0.05, 20.0)]
    samples = [[120, 240], [130, 250], [125, 245]]
    events = [(1, 2, "Sensor calibration ping")]
    (target_dir / "02_valid.lab").write_bytes(build_real_lablog(channels, samples, events))

    # 3. Valid VAULT (encrypted container archive with rolling XOR)
    vault_entries = [
        (1, "manifest.txt", b"VAULT demo manifest v1.0: All records secured."),
        (2, "payload.bin", b"\xDE\xAD\xBE\xEF" * 16),
    ]
    (target_dir / "03_valid.vlt").write_bytes(build_real_vault(vault_entries, xor_key=0x42))

    # 4. Valid Quake PAK (game archive format)
    pak_files = [
        ("maps/demo.bsp", b"BSP_MAP_GEOMETRY_STREAM_DATA"),
        ("config.cfg", b"bind mouse1 +attack\n"),
    ]
    (target_dir / "04_valid.pak").write_bytes(build_real_pak(pak_files))

    # 5. Valid Lotus 1-2-3 Release 1A .WKS (legacy spreadsheet)
    int_payload = bytes([0x00]) + struct.pack("<HHh", 0, 0, 100)
    lbl_payload = bytes([0xFF]) + struct.pack("<HH", 1, 0) + b"'Annual Budget\x00"
    (target_dir / "05_valid.wks").write_bytes(build_real_wks([(0x000D, int_payload), (0x000F, lbl_payload)]))

    # 6. Truncated file (PAK file with directory truncated)
    (target_dir / "06_truncated.pak").write_bytes(build_real_pak(pak_files, truncate_bytes=30))

    # 7. File with unparsed damaged bytes (LIBRA-98 with leading corrupted bytes)
    (target_dir / "07_damaged_stream.lib").write_bytes(
        build_real_libra98(libra_records, inject_unparsed_before_rec=b"\xDE\xAD\xBE\xEF\x99\x88")
    )

    # 8. Unknown / random bytes file
    (target_dir / "08_unknown.bin").write_bytes(
        b"\x7fELF_FAKE_BINARY_STREAM_DOES_NOT_MATCH_ANY_SUPPORTED_MAGIC_BYTES_12345"
    )

    print(f"Successfully created 8 demo fixtures in {target_dir}")

if __name__ == "__main__":
    create_demo_fixtures(Path("demo/input"))
