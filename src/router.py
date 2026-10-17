"""Stage 1: Format Identification Engine.
Identifies formats by header magic bytes first, structural heuristics second, extension last.
"""

from __future__ import annotations
import struct
from typing import NamedTuple

class FormatMatch(NamedTuple):
    format_name: str
    confidence: str  # "HIGH" | "MEDIUM" | "HEURISTIC" | "NONE"
    matched_signature: bytes
    description: str

class FormatRouter:
    """Classifies binary streams into supported legacy formats or UNKNOWN."""

    @classmethod
    def identify(cls, data: bytes, filename: str = "") -> FormatMatch:
        if len(data) == 0:
            return FormatMatch("UNKNOWN", "HIGH", b"", "Empty zero-byte file")

        ext = ""
        if "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()

        # 0. LEGACY_DATA_RECORD container format
        if data.startswith(b"LEGACY_DATA_RECORD"):
            # Extract FORMAT=... from line 2 if present
            fmt = "LEGACY_RECORD"
            first_chunk = data[:256].decode("latin1", errors="replace")
            for line in first_chunk.split("\n"):
                if line.startswith("FORMAT="):
                    fmt = line.split("=", 1)[1].strip().upper()
                    break
            return FormatMatch(fmt, "HIGH", b"LEGACY_DATA_RECORD", f"Legacy container format ({fmt})")

        # 1. LIBRA-98: Magic b"LIBRA98\x00" or b"LB98" or b"LIB98" or b"LBR8"
        if data.startswith(b"LIBRA98\x00") or data.startswith(b"LB98") or data.startswith(b"LIB98") or data.startswith(b"LBR8"):
            return FormatMatch("LIBRA-98", "HIGH", data[:4], "LIBRA-98 library database")

        # 2. LABLOG: Magic b"LABLOG" or b"LLOG" at offset 0, OR repeating block sync b"\xAA\x55"
        if data.startswith(b"LABLOG") or data.startswith(b"LLOG"):
            return FormatMatch("LABLOG", "HIGH", data[:4], "LABLOG laboratory instrument log")
        if len(data) >= 28 and data.startswith(b"\xAA\x55") and b"\xAA\x55" in data[2:]:
            return FormatMatch("LABLOG", "MEDIUM", b"\xAA\x55", "LABLOG sync-framed telemetry stream")

        # 3. VAULT: Magic b"VAULT" or b"VLT1"
        if data.startswith(b"VAULT") or data.startswith(b"VLT1"):
            return FormatMatch("VAULT", "HIGH", data[:4], "VAULT encrypted container archive")

        # 4. WAD: Magic b"IWAD" or b"PWAD" at offset 0 + valid int32 lump count
        if data.startswith(b"IWAD") or data.startswith(b"PWAD"):
            if len(data) >= 12:
                numlumps, infotableofs = struct.unpack("<ii", data[4:12])
                if numlumps >= 0 and infotableofs >= 0:
                    return FormatMatch("WAD", "HIGH", data[:4], "Doom WAD game data archive")
            return FormatMatch("WAD", "MEDIUM", data[:4], "Doom WAD game data archive")

        # 5. PAK: Magic b"PACK" at offset 0
        if data.startswith(b"PACK"):
            if len(data) >= 12:
                dirofs, dirlen = struct.unpack("<ii", data[4:12])
                if dirofs >= 0 and dirlen >= 0:
                    return FormatMatch("PAK", "HIGH", b"PACK", "Quake PAK game data archive")
            return FormatMatch("PAK", "MEDIUM", b"PACK", "Quake PAK game data archive")

        # 6. WPD: Magic b"\xFFWPC" at offset 0
        if data.startswith(b"\xFFWPC"):
            return FormatMatch("WPD", "HIGH", b"\xFFWPC", "WordPerfect document")

        # 7. WKS: Lotus 1-2-3 / Symphony / MS Works
        if (
            data.startswith(b"\x00\x00\x02\x00\x04\x04")
            or data.startswith(b"\x00\x00\x02\x00\x05\x04")
            or data.startswith(b"\x00\x00\x02\x00\x06\x04")
            or data.startswith(b"\x00\x00\x02\x00")
            or data.startswith(b"\xFF\x00\x02\x00")
        ):
            return FormatMatch("WKS", "HIGH", data[:4], "Lotus 1-2-3 spreadsheet")

        # 8. CVT: Commodore GEOS Convert
        if len(data) >= 50 and (b"PRG formatted GEOS file" in data[:64] or b"SEQ formatted GEOS file" in data[:64]):
            return FormatMatch("CVT", "HIGH", b"GEOS", "Commodore 64 GEOS Convert disk image")
        if len(data) >= 30 and data[0] == 0x83 and b"GEOS" in data[:64]:
            return FormatMatch("CVT", "HIGH", b"GEOS", "Commodore 64 GEOS Convert disk image")

        # 9. EBCDIC-DUMP: IBM mainframe tape dump
        if len(data) >= 20 and (
            "STUDENT EXTRACT".encode("cp037") in data[:64]
            or b"\xC8\xE2\xE3\xE4\xC4\xC5\xD5\xE3" in data[:64]
            or (ext == "000" and data[4:5] == b"\xC8")
        ):
            return FormatMatch("EBCDIC-DUMP", "HIGH", b"\xC8", "IBM Mainframe EBCDIC tape dump")

        # 10. BRAVO: Xerox Alto Bravo Document
        if not data.startswith(b"\x89PNG") and b"\x1a" in data and b"\r" in data:
            p_1a = data.find(b"\x1a")
            text_prefix = data[:p_1a]
            if len(text_prefix) > 0 and all(32 <= b <= 126 or b in (9, 10, 13) for b in text_prefix):
                return FormatMatch("BRAVO", "HIGH", b"\x1a", "Xerox Alto Bravo document")

        # 11. ARCHIVE-000: b"000\x1A" or b"WSTD" or header with uint16 count + 8.3 filenames
        if data.startswith(b"000\x1A") or data.startswith(b"WSTD"):
            return FormatMatch("ARCHIVE-000", "HIGH", data[:4], "DOS ARCHIVE-000 container")

        # Heuristics based on extension as weak hint
        if ext == "wad":
            return FormatMatch("WAD", "HEURISTIC", b"", "WAD by extension")
        if ext == "pak":
            return FormatMatch("PAK", "HEURISTIC", b"", "PAK by extension")
        if ext == "wks":
            return FormatMatch("WKS", "HEURISTIC", b"", "WKS by extension")
        if ext == "wpd":
            return FormatMatch("WPD", "HEURISTIC", b"", "WPD by extension")
        if ext == "bravo":
            return FormatMatch("BRAVO", "HEURISTIC", b"", "Bravo by extension")
        if ext == "cvt":
            return FormatMatch("CVT", "HEURISTIC", b"", "CVT by extension")
        if ext == "000":
            return FormatMatch("EBCDIC-DUMP", "HEURISTIC", b"", "EBCDIC/Archive 000 by extension")

        # Fallback
        return FormatMatch(
            format_name="UNKNOWN",
            confidence="NONE",
            matched_signature=b"",
            description="Unknown signature or unstructured binary",
        )

# For backward compatibility
FormatDetector = FormatRouter
