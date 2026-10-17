"""Stage 3/4: Kaitai Struct Runtime.
Provides declarative .ksy specification loading and stream bindings.
"""

from __future__ import annotations
import pathlib
from typing import Optional, Any
from src.ddrescue_cursor import SafeKaitaiStream

class KaitaiRuntime:
    """Lightweight declarative Kaitai Struct loader and runner."""

    @staticmethod
    def load_spec(format_name: str) -> Optional[str]:
        spec_map = {
            "LIBRA-98": "libra98.ksy",
            "LABLOG": "lablog.ksy",
            "VAULT": "vault.ksy",
            "WKS": "wks.ksy",
            "WPD": "wpd.ksy",
            "WAD": "wad_pak.ksy",
            "PAK": "wad_pak.ksy",
        }
        fname = spec_map.get(format_name)
        if not fname:
            return None
        spec_path = pathlib.Path(__file__).parent.parent / "specs" / fname
        if spec_path.exists():
            try:
                return spec_path.read_text(encoding="utf-8")
            except Exception:
                return None
        return None

    @staticmethod
    def create_stream(data: bytes, filename: str = "") -> SafeKaitaiStream:
        return SafeKaitaiStream(data, filename)
