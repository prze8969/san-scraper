"""Recovery pipeline orchestrator with generic analysis and data recovery layer."""

from __future__ import annotations
from pathlib import Path
from src.reader import BoundedBinaryReader
from src.detector import FormatDetector
from src.detector_pipeline import PipelineDetector, SUPPORTED_FORMATS
from src.analysis.file_analyzer import FileAnalyzer
from src.recovery.carver import Carver, GenericRecovery
from src.models import FileRecoveryResult
from src.formats.base import BaseParser
from src.formats.unknown import UnknownParser
from src.formats.libra98 import Libra98Parser
from src.formats.lablog import LablogParser
from src.formats.vault import VaultParser
from src.formats.pak import PakParser
from src.formats.wks import WksParser
from src.formats.wad import WadParser
from src.formats.zip import ZipParser
from src.formats.gzip import GzipParser
from src.formats.png import PngParser
from src.recovery.extractor import extract_container_files

class SalvageEngine:
    """Coordinates reading, detection, parsing, generic analysis, and carving recovery."""

    def __init__(self, output_dir: Path | str | None = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else None
        self._parsers: dict[str, BaseParser] = {
            "UNKNOWN": UnknownParser(),
            "EMPTY": UnknownParser(),
            "LIBRA-98": Libra98Parser(),
            "LABLOG": LablogParser(),
            "VAULT": VaultParser(),
            "PAK": PakParser(),
            "WKS": WksParser(),
            "WAD": WadParser(),
            "ZIP": ZipParser(),
            "GZIP": GzipParser(),
            "PNG": PngParser(),
        }

    def register_parser(self, format_name: str, parser: BaseParser) -> None:
        self._parsers[format_name] = parser

    def process_bytes(
        self,
        filename: str,
        data: bytes,
        output_dir: Path | str | None = None,
    ) -> FileRecoveryResult:
        effective_out_dir = output_dir or self.output_dir

        # 1. Generic File Analysis (Step 1)
        analyzer = FileAnalyzer(data, filename=filename)
        analysis_data = analyzer.analyze()

        # 2. Pipeline Detection (Step 2)
        candidates = PipelineDetector.detect_candidates(data, analysis_data, filename=filename)
        top_candidate = candidates[0]

        # 3. Choose Parser and Parse
        result = self._execute_parser(filename, data, top_candidate, candidates)

        # 4. Extract container files for known archive formats (PAK, WAD, ZIP, GZIP)
        if result.format_name in ("PAK", "WAD", "ZIP", "GZIP") and result.is_valid_header:
            extract_container_files(result, data, output_dir=effective_out_dir)

        # 5. Generic Carving of embedded objects (Step 3)
        carved_objects = Carver.carve_all(
            data,
            analysis_data.get("signatures", []),
            output_dir=effective_out_dir,
            base_filename=filename,
        )

        # 6. Generic / Heuristic Recovery if UNKNOWN, or supplemental for damaged files
        verified_ranges: list[tuple[int, int]] = []
        heuristic_ranges: list[tuple[int, int]] = []

        for r in result.recovered_records:
            if r.fields.get("recovery_lane") == "heuristic":
                heuristic_ranges.append(r.byte_range)
            else:
                verified_ranges.append(r.byte_range)

        for c in carved_objects:
            if c.get("carved") and "byte_range" in c:
                br = c["byte_range"]
                # Carved objects are recovered from container boundaries
                heuristic_ranges.append((br[0], br[1]))

        # If format is UNKNOWN or header corrupted with 0 records recovered, add heuristic records
        if result.format_name in ("UNKNOWN", "EMPTY") or len(result.recovered_records) == 0:
            heuristic_records = GenericRecovery.recover_heuristic_records(data, analysis_data)
            for hr in heuristic_records:
                result.recovered_records.append(hr)
                heuristic_ranges.append(hr.byte_range)

        # 6. Coverage calculation: split into verified and heuristic
        coverage_data = GenericRecovery.calculate_coverage(
            len(data),
            verified_ranges=verified_ranges,
            heuristic_ranges=heuristic_ranges,
        )

        # 7. Forensic Probe Battery (300+ probes) & Layout Documentation
        from src.probes.probe_runner import ProbeRunner
        from src.probes.probe_documenter import ProbeDocumenter
        probe_runner = ProbeRunner(data, filename=filename)
        probes = probe_runner.run_all_probes()

        layout: list[dict[str, Any]] = []
        if effective_out_dir:
            try:
                _, _, layout = ProbeDocumenter.document_probes(
                    effective_out_dir, filename, data, probes, result
                )
            except Exception:
                layout = ProbeDocumenter._infer_layout(data, probes, result)
        else:
            layout = ProbeDocumenter._infer_layout(data, probes, result)

        probe_summary = {
            "total_probes": len(probes),
            "matched_probes": len([p for p in probes if p.result == "match"]),
        }

        # 8. Wire in analysis, detection candidates, carved objects, coverage, probes, layout
        result.analysis = analysis_data
        result.detection_candidates = [c.to_dict() for c in candidates]
        result.carved_objects = carved_objects
        result.coverage = coverage_data
        result.probe_summary = probe_summary
        result.layout = layout

        return result

    def _execute_parser(
        self,
        filename: str,
        data: bytes,
        top_candidate,
        all_candidates,
    ) -> FileRecoveryResult:
        size = len(data)
        if size == 0:
            return self._parsers["EMPTY"].parse(filename, BoundedBinaryReader(data))

        # Check if exact magic at offset 0
        if top_candidate.detection_method == "exact_magic_offset_0":
            parser = self._parsers.get(top_candidate.format_name, self._parsers["UNKNOWN"])
            return parser.parse(filename, BoundedBinaryReader(data))

        # Check if magic at non-zero offset for a supported format
        if top_candidate.detection_method == "magic_nonzero_offset" and top_candidate.format_name in SUPPORTED_FORMATS:
            offset = top_candidate.offset
            sub_reader = BoundedBinaryReader(data[offset:])
            parser = self._parsers.get(top_candidate.format_name)
            if parser:
                sub_res = parser.parse(filename, sub_reader)
                # Adjust record and damage byte ranges by offset
                adjusted_records = []
                for rec in sub_res.recovered_records:
                    rec.byte_range = (rec.byte_range[0] + offset, rec.byte_range[1] + offset)
                    adjusted_records.append(rec)
                for d in sub_res.damages:
                    d.offset += offset
                sub_res.file_size = size
                sub_res.metadata["wrapped_offset"] = offset
                return sub_res

        # Try lenient parsing on supported format candidates if header-corrupted
        supported_candidates = [
            c for c in all_candidates
            if c.format_name in SUPPORTED_FORMATS and c.confidence > 0.3
        ]
        if supported_candidates:
            best_res: FileRecoveryResult | None = None
            best_valid_count = -1
            for cand in supported_candidates:
                parser = self._parsers.get(cand.format_name)
                if not parser:
                    continue
                try:
                    cand_res = parser.parse(filename, BoundedBinaryReader(data))
                    valid_count = sum(1 for r in cand_res.recovered_records if r.status.value in ("complete", "partial"))
                    if valid_count > best_valid_count:
                        best_valid_count = valid_count
                        best_res = cand_res
                except Exception:
                    continue

            if best_res and best_valid_count > 0:
                return best_res

        # Fallback to UNKNOWN parser
        return self._parsers["UNKNOWN"].parse(filename, BoundedBinaryReader(data))

    def process_file(
        self,
        file_path: Path,
        output_dir: Path | str | None = None,
    ) -> FileRecoveryResult:
        filename = file_path.name
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self.process_bytes(filename, data, output_dir=output_dir)
        except Exception as e:
            from src.models import DamageBlock, DamageType
            return FileRecoveryResult(
                filename=filename,
                format_name="ERROR",
                file_size=0,
                is_valid_header=False,
                total_records=0,
                damages=[
                    DamageBlock(
                        offset=0,
                        length=0,
                        damage_type=DamageType.TRUNCATION,
                        description=f"File read error: {str(e)}",
                    )
                ],
                metadata={"error": str(e)},
            )
