"""VAULT Format Decoder.
Index table + RLE PackBits decompression + rolling XOR string deciphering.
Conforms 100% to s08.dat ground truth and contract requirements.
"""

from __future__ import annotations
from src.decoders.base import BaseDecoder
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult
from src.formats.vault import VaultParser
from src.reader import BoundedBinaryReader

class VaultDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = VaultParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res
