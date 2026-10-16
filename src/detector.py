"""Format detection based on signatures and structural evidence."""

from __future__ import annotations
from typing import NamedTuple

class FormatMatch(NamedTuple):
    format_name: str
    confidence: float  # 0.0 to 1.0
    matched_signature: bytes
    description: str

class FormatDetector:
    """Dispatches binary inputs to matching parsers based on signature or heuristic."""

    KNOWN_SIGNATURES: list[tuple[str, bytes, int, str]] = [
        # format_name, signature_bytes, offset, description
        ("LIBRA-98", b"LB98", 0, "LIBRA-98 library database"),
        ("LABLOG", b"LLOG", 0, "Laboratory Log journal"),
        ("VAULT", b"VLT1", 0, "VAULT archive storage"),
        ("PAK", b"PACK", 0, "id Software Quake PAK archive"),
        ("WAD", b"IWAD", 0, "Doom Internal WAD"),
        ("WAD", b"PWAD", 0, "Doom Patch WAD"),
        ("WKS", b"\x00\x00\x02\x00", 0, "Lotus 1-2-3 BOF record"),
        ("ZIP", b"PK\x03\x04", 0, "ZIP archive"),
        ("GZIP", b"\x1f\x8b", 0, "GZIP compressed archive"),
        ("PNG", b"\x89PNG\r\n\x1a\n", 0, "Portable Network Graphics"),
    ]

    @classmethod
    def detect(cls, data: bytes) -> FormatMatch:
        """Inspects magic bytes and header structure to identify the format."""
        if len(data) == 0:
            return FormatMatch(
                format_name="EMPTY",
                confidence=1.0,
                matched_signature=b"",
                description="Empty zero-byte file",
            )

        # Check known fixed signatures
        for fmt_name, sig, offset, desc in cls.KNOWN_SIGNATURES:
            sig_len = len(sig)
            if len(data) >= offset + sig_len and data[offset:offset + sig_len] == sig:
                return FormatMatch(
                    format_name=fmt_name,
                    confidence=1.0,
                    matched_signature=sig,
                    description=desc,
                )

        return FormatMatch(
            format_name="UNKNOWN",
            confidence=0.0,
            matched_signature=b"",
            description="Unknown signature or unstructured binary",
        )
