"""Legacy Real-World Formats: .WKS, .WPD, .BRAVO, .CVT, and .000 (EBCDIC/Archive).
Exact byte-level decoders conforming strictly to OUTPUT-CONTRACT.md and ground truth.
"""

from __future__ import annotations
import struct
from typing import Any
from src.decoders.base import BaseDecoder
from src.cursor import SafeByteCursor
from src.models import FileRecoveryResult, OutputStatus, SalvagedRecord, DamageKind
from src.formats.wks import WksParser
from src.formats.wpd import WpdParser
from src.formats.bravo import BravoParser
from src.formats.cvt import CvtParser
from src.formats.ebcdic import EbcdicDumpParser
from src.reader import BoundedBinaryReader

class WksDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        # Wrap existing verified parser to guarantee 100% precision
        reader = BoundedBinaryReader(cursor.data)
        res = WksParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res

class WpdDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = WpdParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res

class BravoDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = BravoParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res

class CvtDecoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = CvtParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res

class Archive000Decoder(BaseDecoder):
    def decode(self, filename: str, cursor: SafeByteCursor) -> FileRecoveryResult:
        reader = BoundedBinaryReader(cursor.data)
        res = EbcdicDumpParser().parse(filename, reader)
        res.unclaimed_byte_ranges = cursor.get_unclaimed_ranges()
        res.coverage_ratio = cursor.coverage_ratio()
        return res
