"""Recovery pipeline orchestrator conforming to OUTPUT-CONTRACT.md and Phase 1-6 specification."""

from __future__ import annotations
from pathlib import Path
from src.cursor import SafeByteCursor
from src.reader import BoundedBinaryReader
from src.router import FormatRouter
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind, DamageEvent
from src.formats.base import BaseParser
from src.formats.unknown import UnknownParser
from src.decoders.libra98 import Libra98Decoder
from src.decoders.lablog import LablogDecoder
from src.decoders.vault import VaultDecoder
from src.decoders.wad_pak import WadDecoder, PakDecoder
from src.decoders.legacy_real import WksDecoder, WpdDecoder, BravoDecoder, CvtDecoder, Archive000Decoder
from src.decoders.legacy_record import LegacyRecordDecoder

import hashlib
import copy

class SalvageEngine:
    """Coordinates reading, detection, parsing, and recovery with zero-crash guarantee."""

    def __init__(self) -> None:
        self._cache: dict[str, FileRecoveryResult] = {}
        self._cache_hits: int = 0
        self._cache_misses: int = 0
        self._legacy_decoder = LegacyRecordDecoder()
        self._decoders = {
            "UNKNOWN": UnknownParser(),
            "EMPTY": UnknownParser(),
            "LIBRA-98": Libra98Decoder(),
            "LABLOG": LablogDecoder(),
            "VAULT": VaultDecoder(),
            "WAD": WadDecoder(),
            "PAK": PakDecoder(),
            "WKS": WksDecoder(),
            "WPD": WpdDecoder(),
            "BRAVO": BravoDecoder(),
            "CVT": CvtDecoder(),
            "EBCDIC-DUMP": Archive000Decoder(),
            "ARCHIVE-000": Archive000Decoder(),
            "LEGACY_RECORD": self._legacy_decoder,
        }

    def clear_cache(self) -> None:
        """Clears the in-memory deduplication cache."""
        self._cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

    @property
    def cache_stats(self) -> dict[str, int]:
        return {
            "cached_entries": len(self._cache),
            "hits": self._cache_hits,
            "misses": self._cache_misses,
        }

    def register_parser(self, format_name: str, parser: Any) -> None:
        self._decoders[format_name] = parser

    def process_bytes(self, filename: str, data: bytes) -> FileRecoveryResult:
        # Check in-memory content-addressable hash cache for instant deduplication
        content_hash = hashlib.sha256(data).hexdigest()
        if content_hash in self._cache:
            self._cache_hits += 1
            cached = self._cache[content_hash]
            cloned = copy.copy(cached)
            cloned.filename = filename
            cloned.source_file = filename
            cloned.records = copy.deepcopy(cached.records)
            cloned.damages = copy.deepcopy(cached.damages)
            cloned.metadata = copy.deepcopy(cached.metadata)
            cloned.damage_events = list(cached.damage_events)
            return cloned

        self._cache_misses += 1
        match = FormatRouter.identify(data, filename)
        cursor = SafeByteCursor(data)
        decoder = self._decoders.get(match.format_name)
        if decoder is None:
            if data.startswith(b"LEGACY_DATA_RECORD"):
                decoder = self._legacy_decoder
            else:
                decoder = self._decoders["UNKNOWN"]

        try:
            if hasattr(decoder, "decode"):
                res = decoder.decode(filename, cursor)
            else:
                reader = BoundedBinaryReader(data)
                res = decoder.parse(filename, reader)
            res.detected_format = match.format_name
            res.confidence = match.confidence
            self._cache[content_hash] = res
            return res
        except Exception as e:
            cursor.log_damage(
                severity="ERROR",
                component="engine_exception",
                message=f"Handled internal exception: {e}",
                offset_start=0,
                offset_end=len(data),
                legacy_kind=DamageKind.INVALID_VALUE,
            )
            return FileRecoveryResult(
                filename=filename,
                format_name=match.format_name if match.format_name != "EMPTY" else "UNKNOWN",
                status=OutputStatus.FAILED,
                damages=cursor.legacy_damages,
                damage_events=cursor.damages,
                metadata={"error": str(e)},
                file_size=len(data),
            )

    def process_file(self, file_path: Path) -> FileRecoveryResult:
        filename = file_path.name
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.process_bytes(filename, data)
        except Exception as e:
            return FileRecoveryResult(
                filename=filename,
                format_name="UNKNOWN",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail=f"File read error: {str(e)}",
                        lossy=True,
                    )
                ],
                metadata={"error": str(e)},
            )
