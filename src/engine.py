"""Recovery pipeline orchestrator conforming to OUTPUT-CONTRACT.md."""

from __future__ import annotations
from pathlib import Path
from src.reader import BoundedBinaryReader
from src.detector import FormatDetector
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind
from src.formats.base import BaseParser
from src.formats.unknown import UnknownParser
from src.formats.libra98 import Libra98Parser
from src.formats.lablog import LablogParser
from src.formats.vault import VaultParser
from src.formats.pak import PakParser
from src.formats.wks import WksParser
from src.formats.wpd import WpdParser
from src.formats.bravo import BravoParser
from src.formats.cvt import CvtParser
from src.formats.ebcdic import EbcdicDumpParser
from src.formats.wad import WadParser

class SalvageEngine:
    """Coordinates reading, detection, parsing, and recovery."""

    def __init__(self) -> None:
        self._parsers: dict[str, BaseParser] = {
            "UNKNOWN": UnknownParser(),
            "EMPTY": UnknownParser(),
            "LIBRA-98": Libra98Parser(),
            "LABLOG": LablogParser(),
            "VAULT": VaultParser(),
            "PAK": PakParser(),
            "WKS": WksParser(),
            "WPD": WpdParser(),
            "BRAVO": BravoParser(),
            "CVT": CvtParser(),
            "EBCDIC-DUMP": EbcdicDumpParser(),
            "WAD": WadParser(),
        }

    def register_parser(self, format_name: str, parser: BaseParser) -> None:
        self._parsers[format_name] = parser

    def process_bytes(self, filename: str, data: bytes) -> FileRecoveryResult:
        match = FormatDetector.detect(data)
        reader = BoundedBinaryReader(data)
        parser = self._parsers.get(match.format_name, self._parsers["UNKNOWN"])
        return parser.parse(filename, reader)

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
