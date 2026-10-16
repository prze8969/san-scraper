"""Candidate detection and multi-stage classification pipeline."""

from __future__ import annotations
from typing import NamedTuple, Any
from src.analysis.file_analyzer import SIGNATURE_DATABASE

SUPPORTED_FORMATS = {"LIBRA-98", "LABLOG", "VAULT", "PAK", "WKS", "WAD", "ZIP", "GZIP", "PNG"}

EXTENSION_MAP = {
    "lib": "LIBRA-98",
    "lab": "LABLOG",
    "vlt": "VAULT",
    "pak": "PAK",
    "wks": "WKS",
    "123": "WKS",
    "zip": "ZIP",
    "png": "PNG",
    "gif": "GIF",
    "jpg": "JPEG",
    "jpeg": "JPEG",
    "pdf": "PDF",
    "gz": "GZIP",
    "db": "SQLite",
    "sqlite": "SQLite",
    "wav": "RIFF",
    "avi": "RIFF",
}

class DetectionCandidate(NamedTuple):
    format_name: str
    confidence: float  # 0.0 to 1.0
    detection_method: str  # exact_magic_offset_0, magic_nonzero_offset, structural_match, extension_hint, fallback
    offset: int
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format_name,
            "confidence": round(self.confidence, 3),
            "method": self.detection_method,
            "offset": self.offset,
            "evidence": self.evidence,
        }

class PipelineDetector:
    """Scored detection pipeline ranking candidate formats."""

    @classmethod
    def detect_candidates(
        cls,
        data: bytes,
        analysis_data: dict[str, Any] | None = None,
        filename: str = "",
    ) -> list[DetectionCandidate]:
        candidates: list[DetectionCandidate] = []
        size = len(data)

        if size == 0:
            return [
                DetectionCandidate(
                    format_name="EMPTY",
                    confidence=1.0,
                    detection_method="exact_magic_offset_0",
                    offset=0,
                    evidence="File is 0 bytes",
                )
            ]

        # 1. Exact magic at offset 0
        for fmt, sig, desc in SIGNATURE_DATABASE:
            sig_len = len(sig)
            if size >= sig_len and data[:sig_len] == sig:
                candidates.append(
                    DetectionCandidate(
                        format_name=fmt,
                        confidence=1.0,
                        detection_method="exact_magic_offset_0",
                        offset=0,
                        evidence=f"Exact magic match at offset 0: {desc}",
                    )
                )

        # 2. Magic at non-zero offset (header-damaged or wrapped file)
        if analysis_data and "signatures" in analysis_data:
            sig_matches = analysis_data["signatures"]
        else:
            # Inline search if analysis_data not provided
            sig_matches = []
            for fmt, sig, desc in SIGNATURE_DATABASE:
                idx = data.find(sig)
                if idx > 0:
                    sig_matches.append({
                        "format": fmt,
                        "offset": idx,
                        "confidence": 0.85,
                        "description": desc,
                    })

        for match in sig_matches:
            if match["offset"] > 0:
                candidates.append(
                    DetectionCandidate(
                        format_name=match["format"],
                        confidence=0.85,
                        detection_method="magic_nonzero_offset",
                        offset=match["offset"],
                        evidence=f"Magic found at non-zero offset {match['offset']}: {match.get('description', '')}",
                    )
                )

        # 3. Structural match (from heuristics)
        if analysis_data and "heuristics" in analysis_data:
            for h in analysis_data["heuristics"]:
                htype = h.get("heuristic")
                if htype == "repeated_sync_marker" and h.get("details", {}).get("marker") == "BLOK":
                    candidates.append(
                        DetectionCandidate(
                            format_name="LABLOG",
                            confidence=0.75,
                            detection_method="structural_match",
                            offset=h.get("details", {}).get("first_offsets", [0])[0],
                            evidence="LABLOG block sync markers (BLOK) detected across stream",
                        )
                    )
                elif htype == "fixed_width_record_stride":
                    stride = h.get("details", {}).get("stride_bytes")
                    if stride == 48:
                        candidates.append(
                            DetectionCandidate(
                                format_name="LIBRA-98",
                                confidence=0.70,
                                detection_method="structural_match",
                                offset=0,
                                evidence="48-byte record stride matching LIBRA-98 record specifications",
                            )
                        )

        # 4. Extension hint
        ext = None
        if filename and "." in filename:
            ext = filename.rsplit(".", 1)[-1].lower()
        elif analysis_data and analysis_data.get("extension_hint"):
            ext = analysis_data["extension_hint"]

        if ext and ext in EXTENSION_MAP:
            mapped_fmt = EXTENSION_MAP[ext]
            # Extension confidence is modest (0.4)
            candidates.append(
                DetectionCandidate(
                    format_name=mapped_fmt,
                    confidence=0.40,
                    detection_method="extension_hint",
                    offset=0,
                    evidence=f"File extension '.{ext}' hints at {mapped_fmt}",
                )
            )

        # Deduplicate candidates by format name keeping highest confidence
        best_by_fmt: dict[str, DetectionCandidate] = {}
        for c in candidates:
            if c.format_name not in best_by_fmt or c.confidence > best_by_fmt[c.format_name].confidence:
                best_by_fmt[c.format_name] = c

        sorted_candidates = sorted(best_by_fmt.values(), key=lambda c: (-c.confidence, c.offset))

        if not sorted_candidates:
            sorted_candidates.append(
                DetectionCandidate(
                    format_name="UNKNOWN",
                    confidence=0.0,
                    detection_method="fallback",
                    offset=0,
                    evidence="No matching magic or known structure found",
                )
            )

        return sorted_candidates
