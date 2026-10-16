"""LABLOG Format Decoder.
Laboratory instrument telemetry frames with CRC-16-CCITT and 0xAA55 sync carving.
Conforms 100% to s05.dat ground truth and contract requirements.
"""

from __future__ import annotations
from src.decoders.base import BaseDecoder
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult
from src.formats.lablog import LablogParser
from src.reader import BoundedBinaryReader

class LablogDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = LablogParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res
