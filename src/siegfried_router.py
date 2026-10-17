"""Stage 1: Siegfried / PRONOM Identifier.
Evaluates PRONOM-style rules from specs/pronom_signatures.json to identify legacy binary formats.
"""

from __future__ import annotations
import json
import pathlib
from typing import Tuple, Optional, Any
from src.router import FormatDetector, FormatIdentification

class SiegfriedRouter:
    """PRONOM-style format router loaded from declarative signatures."""

    def __init__(self, signatures_path: Optional[str] = None):
        self.signatures: list[dict[str, Any]] = []
        if signatures_path is None:
            base_dir = pathlib.Path(__file__).parent.parent
            signatures_path = str(base_dir / "specs" / "pronom_signatures.json")
        
        sig_file = pathlib.Path(signatures_path)
        if sig_file.exists():
            try:
                with open(sig_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.signatures = data.get("signatures", [])
            except Exception:
                self.signatures = []

    def identify(self, data: bytes, filename: str = "") -> FormatIdentification:
        """Evaluates PRONOM BOF/offset magic and structural heuristics."""
        # Check declarative signatures first
        for sig in self.signatures:
            bof_hex = sig.get("bof_magic_hex")
            offset = sig.get("offset", 0)
            if bof_hex:
                magic_bytes = bytes.fromhex(bof_hex)
                if len(data) >= offset + len(magic_bytes):
                    if data[offset:offset+len(magic_bytes)] == magic_bytes:
                        return FormatIdentification(
                            format_name=sig["format_name"],
                            confidence=0.95,
                            detection_method=f"pronom_sig:{sig['id']}",
                        )

        # Fallback to full multi-layer FormatDetector
        return FormatDetector.detect(data, filename)
