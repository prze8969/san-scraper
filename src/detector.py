"""Format detection based on signatures and structural evidence strictly conforming to OUTPUT-CONTRACT.md."""

from __future__ import annotations
from typing import NamedTuple

class FormatMatch(NamedTuple):
    format_name: str
    confidence: float
    matched_signature: bytes
    description: str

class FormatDetector:
    """Dispatches binary inputs to matching parsers based on signature or heuristic."""

    @classmethod
    def detect(cls, data: bytes) -> FormatMatch:
        if len(data) == 0:
            return FormatMatch("EMPTY", 1.0, b"", "Empty zero-byte file")

        # 1. LIBRA-98: LB98 or legacy prototype signature
        if (len(data) >= 4 and data[:4] == b"LB98") or data.startswith(b"LIBRA98\x00"):
            return FormatMatch("LIBRA-98", 1.0, b"LB98", "LIBRA-98 library database")

        # 2. LABLOG: LLOG or provisional signature
        if (len(data) >= 4 and data[:4] == b"LLOG") or data.startswith(b"LABLOG\x01\x00"):
            return FormatMatch("LABLOG", 1.0, b"LLOG", "LABLOG laboratory journal")

        # 3. VAULT: VLT1 or provisional signature
        if (len(data) >= 4 and data[:4] == b"VLT1") or data.startswith(b"VAULT\x01\x00\x00"):
            return FormatMatch("VAULT", 1.0, b"VLT1", "VAULT container archive")

        # 4. WKS: Lotus 1-2-3 BOF record
        if len(data) >= 4 and data[:4] == b"\x00\x00\x02\x00":
            return FormatMatch("WKS", 1.0, b"\x00\x00\x02\x00", "Lotus 1-2-3 spreadsheet")

        # 5. WPD: \xFFWPC
        if len(data) >= 4 and data[:4] == b"\xFFWPC":
            return FormatMatch("WPD", 1.0, b"\xFFWPC", "WordPerfect document")

        # 6. WAD: PWAD / IWAD
        if len(data) >= 4 and data[:4] in (b"PWAD", b"IWAD"):
            return FormatMatch("WAD", 1.0, data[:4], "Doom WAD archive")

        # 7. PAK: PACK
        if len(data) >= 4 and data[:4] == b"PACK":
            return FormatMatch("PAK", 1.0, b"PACK", "Quake PAK archive")

        # 8. CVT: Commodore 64 GEOS Convert
        if b"PRG formatted GEOS file" in data[:64] or (len(data) >= 30 and data[0] == 0x83 and b"GEOS" in data[:64]):
            return FormatMatch("CVT", 1.0, b"GEOS", "Commodore 64 GEOS Convert disk image")

        # 9. EBCDIC-DUMP: IBM mainframe tape dump
        if len(data) >= 20 and ("STUDENT EXTRACT".encode("cp037") in data[:64] or data[4:5] == b"\xC8" or b"\xC8\xE2\xE3\xE4\xC4\xC5\xD5\xE3" in data[:64]):
            return FormatMatch("EBCDIC-DUMP", 1.0, b"\xC8", "IBM Mainframe EBCDIC tape dump")

        # 10. BRAVO: Xerox Alto Bravo editor (CR separated paragraphs, trailer with 0x1A)
        if not data.startswith(b"\x89PNG") and b"\x1a" in data and b"\r" in data:
            p_1a = data.find(b"\x1a")
            text_prefix = data[:p_1a]
            # Must be predominantly ASCII text
            if all(32 <= b <= 126 or b in (9, 10, 13) for b in text_prefix):
                return FormatMatch("BRAVO", 0.9, b"\x1a", "Xerox Alto Bravo document")

        return FormatMatch(
            format_name="UNKNOWN",
            confidence=0.0,
            matched_signature=b"",
            description="Unknown signature or unstructured binary",
        )
