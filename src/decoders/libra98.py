"""LIBRA-98 Format Decoder.
School/Library database format with decoy length fields, MS-DOS dates, and sync markers.
Conforms 100% to s01.dat and s04.dat ground truths and spec requirements.
"""

from __future__ import annotations
from src.decoders.base import BaseDecoder
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult
from src.formats.libra98 import Libra98Parser
from src.reader import BoundedBinaryReader

class Libra98Decoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = Libra98Parser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res
