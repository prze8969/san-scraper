"""Output conformance adapter for the judge's OUTPUT-CONTRACT.md.

Produces strictly compliant per-file JSON and report.json without leaking
heuristic records, internal scratch structures, or non-contract keys.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from src.models import FileRecoveryResult, RecordStatus, DamageBlock

CONTRACT_FORMATS = {
    "LIBRA-98",
    "LABLOG",
    "VAULT",
    "WKS",
    "WPD",
    "BRAVO",
    "CVT",
    "EBCDIC-DUMP",
    "WAD",
    "PAK",
    "UNKNOWN",
}

CONTRACT_DAMAGE_KINDS = {
    "truncated",
    "crc_mismatch",
    "checksum_mismatch",
    "bad_length",
    "unparsed_bytes",
    "count_mismatch",
    "invalid_value",
    "oob_pointer",
    "index_missing",
    "header_checksum",
    "encrypted",
    "unknown_record",
}

# Map internal DamageType enum values or strings to contract vocabulary
DAMAGE_TYPE_MAP: dict[str, str] = {
    "truncation": "truncated",
    "truncated": "truncated",
    "checksum_mismatch": "checksum_mismatch",
    "crc_mismatch": "crc_mismatch",
    "invalid_header": "header_checksum",
    "corrupt_record": "unknown_record",
    "malformed_offset": "oob_pointer",
    "unknown_signature": "unknown_record",
    "decompression_error": "bad_length",
    "bad_length": "bad_length",
    "unparsed_bytes": "unparsed_bytes",
    "count_mismatch": "count_mismatch",
    "invalid_value": "invalid_value",
    "oob_pointer": "oob_pointer",
    "index_missing": "index_missing",
    "header_checksum": "header_checksum",
    "encrypted": "encrypted",
    "unknown_record": "unknown_record",
}


def normalize_damage_kind(raw_kind: Any) -> str:
    """Maps any internal damage type to the strict contract vocabulary."""
    val = str(getattr(raw_kind, "value", raw_kind)).lower()
    return DAMAGE_TYPE_MAP.get(val, "unknown_record")


class ConformanceAdapter:
    """Adapts internal FileRecoveryResult to the judges' OUTPUT-CONTRACT.md specification."""

    TOOL_VERSION = "salvage-ps02-v1.0"

    @classmethod
    def to_contract_file_dict(cls, result: FileRecoveryResult) -> dict[str, Any]:
        """Converts an internal FileRecoveryResult into exact judges' per-file JSON."""
        # 1. Normalize format
        fmt = result.format_name.upper()
        if fmt not in CONTRACT_FORMATS:
            if fmt in ("GZIP", "PNG", "EMPTY"):
                fmt = "UNKNOWN"
            else:
                fmt = "UNKNOWN"

        # 2. Determine status: ok | partial | unsupported | unrecognized | failed
        status = "ok"
        verified_records = [
            r for r in result.recovered_records
            if r.fields.get("recovery_lane") != "heuristic"
        ]

        if fmt == "UNKNOWN":
            status = "unrecognized"
        elif not result.is_valid_header and len(verified_records) == 0:
            status = "failed"
        elif any(d.get("kind") == "encrypted" for d in result.metadata.get("damages", [])):
            status = "unsupported"
        else:
            # Check if any records are damaged/partial or if damage blocks exist
            has_damage = len(result.damages) > 0
            has_partial_records = any(
                r.status in (RecordStatus.PARTIAL, RecordStatus.CORRUPTED, RecordStatus.UNRECOVERABLE)
                for r in result.recovered_records
                if r.fields.get("recovery_lane") != "heuristic"
            )
            if has_damage or has_partial_records:
                status = "partial"
            else:
                status = "ok"

        # 3. Filter and normalize records: NO heuristic or guessed records in graded JSON
        contract_records: list[dict[str, Any]] = []
        if status != "unrecognized":
            for r in result.recovered_records:
                # Discard heuristic lane records completely from graded output
                if r.fields.get("recovery_lane") == "heuristic":
                    continue

                # For WKS, only cell records belong in records[] per contract
                if fmt == "WKS" and "cell" not in r.fields:
                    continue

                rec_dict: dict[str, Any] = {}
                # Shallow copy all actual record fields
                for k, v in r.fields.items():
                    if k in ("recovery_lane", "raw_hex", "payload_len", "errors", "record_type", "type"):
                        # Keep type if it's WKS/VAULT/WPD cell/blob type
                        if k == "type" and fmt in ("WKS", "VAULT", "WPD"):
                            rec_dict[k] = v
                        continue
                    rec_dict[k] = v

                # If record is unverified or damaged, mark it per contract
                if r.status in (RecordStatus.PARTIAL, RecordStatus.CORRUPTED, RecordStatus.UNRECOVERABLE):
                    rec_dict["verified"] = False
                    if r.errors:
                        issues = []
                        for err in r.errors:
                            if "crc" in err.lower():
                                issues.append("crc_mismatch")
                            elif "truncate" in err.lower():
                                issues.append("truncated")
                            else:
                                issues.append("invalid_value")
                        if issues:
                            rec_dict["issues"] = issues

                contract_records.append(rec_dict)

        # 4. Normalize damage blocks: damage[{kind, offset, detail, lossy}]
        contract_damage: list[dict[str, Any]] = []
        for d in result.damages:
            kind = normalize_damage_kind(d.damage_type)
            contract_damage.append({
                "kind": kind,
                "offset": d.offset,
                "detail": d.description,
                "lossy": True if kind in ("truncated", "crc_mismatch", "bad_length", "oob_pointer") else False,
            })

        # 5. Extract metadata (strip non-contract internal keys like analysis/probes if nested)
        meta = dict(result.metadata)
        # Avoid leaking internal grid or probe keys if not part of format
        if fmt != "WKS" and "grid" in meta:
            meta.pop("grid", None)
        if fmt == "WKS":
            meta.pop("saw_bof", None)
            meta.pop("saw_eof", None)
            meta.pop("grid", None)

        return {
            "source_file": Path(result.filename).name,
            "format": fmt,
            "status": status,
            "metadata": meta,
            "records": contract_records,
            "damage": contract_damage,
        }

    @classmethod
    def to_sidecar_analysis_dict(cls, result: FileRecoveryResult) -> dict[str, Any]:
        """Preserves rich analysis, probes, carving, and layout in sidecar <name>.analysis.json."""
        return {
            "source_file": Path(result.filename).name,
            "format": result.format_name,
            "file_size": result.file_size,
            "coverage": result.coverage,
            "analysis": result.analysis,
            "detection_candidates": result.detection_candidates,
            "carved_objects": result.carved_objects,
            "probe_summary": result.probe_summary,
            "layout": result.layout,
            "raw_records": [r.to_dict() for r in result.recovered_records],
        }

    @classmethod
    def to_contract_report_dict(cls, file_dicts: list[dict[str, Any]]) -> dict[str, Any]:
        """Builds the exact judges' report.json payload."""
        totals: dict[str, int] = {
            "ok": 0,
            "partial": 0,
            "unsupported": 0,
            "unrecognized": 0,
            "failed": 0,
        }
        files_summary: list[dict[str, Any]] = []

        for fd in file_dicts:
            st = fd.get("status", "failed")
            totals[st] = totals.get(st, 0) + 1
            files_summary.append({
                "file": fd["source_file"],
                "format": fd["format"],
                "status": st,
                "records": len(fd.get("records", [])),
                "damage": len(fd.get("damage", [])),
            })

        return {
            "tool_version": cls.TOOL_VERSION,
            "files": files_summary,
            "totals": totals,
        }
