"""Carving and generic recovery layer for embedded objects and heuristic data.

Carves objects with reliable end markers or length fields (PNG, ZIP, JPEG).
Generates heuristic text records and candidate-record recovery.
Computes byte coverage (recovered vs total unaccounted).
"""

from __future__ import annotations
import hashlib
import struct
from pathlib import Path
from typing import Any
from src.models import RecoveredRecord, RecordStatus

# Max carved file size: 16 MB
MAX_CARVE_BYTES = 16 * 1024 * 1024

class Carver:
    """Bounded carving engine for embedded objects with reliable boundaries."""

    @classmethod
    def carve_all(
        cls,
        data: bytes,
        signatures: list[dict[str, Any]],
        output_dir: Path | str | None,
        base_filename: str,
    ) -> list[dict[str, Any]]:
        carved_results: list[dict[str, Any]] = []
        carve_dir: Path | None = None

        if output_dir:
            carve_dir = Path(output_dir) / f"{base_filename}.carved"

        for sig in signatures:
            fmt = sig["format"]
            offset = sig["offset"]

            # Only attempt carving for formats where boundaries are unambiguously determinable
            if fmt == "PNG":
                cls._carve_png(data, offset, carve_dir, carved_results)
            elif fmt == "ZIP":
                cls._carve_zip(data, offset, carve_dir, carved_results)
            elif fmt == "JPEG":
                cls._carve_jpeg(data, offset, carve_dir, carved_results)
            else:
                # Log why carving was skipped for this signature
                if fmt in ("LIBRA-98", "LABLOG", "VAULT", "PAK", "WKS"):
                    # Supported formats are handled by their specialized parsers, not raw file carver
                    continue
                carved_results.append({
                    "format": fmt,
                    "offset": offset,
                    "carved": False,
                    "reason": f"Carving skipped for {fmt}: ambiguous or unsupported end-boundary definition",
                })

        return carved_results

    @classmethod
    def _carve_png(
        cls,
        data: bytes,
        start_offset: int,
        carve_dir: Path | None,
        results: list[dict[str, Any]],
    ) -> None:
        # PNG has exact IEND chunk: b"IEND\xaeB`\x82" (chunk type + 4-byte CRC)
        iend_marker = b"IEND\xaeB`\x82"
        iend_pos = data.find(iend_marker, start_offset)
        if iend_pos != -1:
            end_offset = iend_pos + len(iend_marker)
            size = end_offset - start_offset
            if size > MAX_CARVE_BYTES:
                results.append({
                    "format": "PNG",
                    "offset": start_offset,
                    "carved": False,
                    "reason": f"Carve size {size} exceeds max bounds {MAX_CARVE_BYTES}",
                })
                return

            carved_bytes = data[start_offset:end_offset]
            sha256 = hashlib.sha256(carved_bytes).hexdigest()
            out_file_name = f"carved_{start_offset:08x}.png"

            if carve_dir:
                try:
                    carve_dir.mkdir(parents=True, exist_ok=True)
                    (carve_dir / out_file_name).write_bytes(carved_bytes)
                except Exception:
                    pass

            results.append({
                "format": "PNG",
                "offset": start_offset,
                "end_offset": end_offset,
                "size": size,
                "sha256": sha256,
                "carved": True,
                "filename": out_file_name,
                "byte_range": [start_offset, end_offset],
            })
        else:
            results.append({
                "format": "PNG",
                "offset": start_offset,
                "carved": False,
                "reason": "Missing required PNG IEND chunk terminator",
            })

    @classmethod
    def _carve_zip(
        cls,
        data: bytes,
        start_offset: int,
        carve_dir: Path | None,
        results: list[dict[str, Any]],
    ) -> None:
        # End of Central Directory record signature: b"PK\x05\x06"
        eocd_marker = b"PK\x05\x06"
        eocd_pos = data.find(eocd_marker, start_offset)
        if eocd_pos != -1 and eocd_pos + 22 <= len(data):
            # EOCD record is at least 22 bytes + comment length
            comment_len = struct.unpack_from("<H", data, eocd_pos + 20)[0]
            end_offset = min(len(data), eocd_pos + 22 + comment_len)
            size = end_offset - start_offset
            if size > MAX_CARVE_BYTES:
                results.append({
                    "format": "ZIP",
                    "offset": start_offset,
                    "carved": False,
                    "reason": f"Carve size {size} exceeds max bounds {MAX_CARVE_BYTES}",
                })
                return

            carved_bytes = data[start_offset:end_offset]
            sha256 = hashlib.sha256(carved_bytes).hexdigest()
            out_file_name = f"carved_{start_offset:08x}.zip"

            if carve_dir:
                try:
                    carve_dir.mkdir(parents=True, exist_ok=True)
                    (carve_dir / out_file_name).write_bytes(carved_bytes)
                except Exception:
                    pass

            results.append({
                "format": "ZIP",
                "offset": start_offset,
                "end_offset": end_offset,
                "size": size,
                "sha256": sha256,
                "carved": True,
                "filename": out_file_name,
                "byte_range": [start_offset, end_offset],
            })
        else:
            results.append({
                "format": "ZIP",
                "offset": start_offset,
                "carved": False,
                "reason": "End-of-Central-Directory (EOCD) signature not found or truncated",
            })

    @classmethod
    def _carve_jpeg(
        cls,
        data: bytes,
        start_offset: int,
        carve_dir: Path | None,
        results: list[dict[str, Any]],
    ) -> None:
        # JPEG End of Image (EOI): b"\xff\xd9"
        eoi_marker = b"\xff\xd9"
        eoi_pos = data.find(eoi_marker, start_offset + 2)
        if eoi_pos != -1:
            end_offset = eoi_pos + 2
            size = end_offset - start_offset
            if size > MAX_CARVE_BYTES:
                results.append({
                    "format": "JPEG",
                    "offset": start_offset,
                    "carved": False,
                    "reason": f"Carve size {size} exceeds max bounds",
                })
                return

            carved_bytes = data[start_offset:end_offset]
            sha256 = hashlib.sha256(carved_bytes).hexdigest()
            out_file_name = f"carved_{start_offset:08x}.jpg"

            if carve_dir:
                try:
                    carve_dir.mkdir(parents=True, exist_ok=True)
                    (carve_dir / out_file_name).write_bytes(carved_bytes)
                except Exception:
                    pass

            results.append({
                "format": "JPEG",
                "offset": start_offset,
                "end_offset": end_offset,
                "size": size,
                "sha256": sha256,
                "carved": True,
                "filename": out_file_name,
                "byte_range": [start_offset, end_offset],
            })
        else:
            results.append({
                "format": "JPEG",
                "offset": start_offset,
                "carved": False,
                "reason": "JPEG End-of-Image (EOI 0xFFD9) marker not found",
            })

class GenericRecovery:
    """Recovers heuristic text and candidate records, and computes coverage."""

    @classmethod
    def recover_heuristic_records(
        cls,
        data: bytes,
        analysis_data: dict[str, Any],
    ) -> list[RecoveredRecord]:
        records: list[RecoveredRecord] = []
        rec_counter = 1

        # 1. Text recovery: strings as heuristic records
        extracted_strings = analysis_data.get("strings", [])
        for s in extracted_strings:
            # We filter out very short trivial strings for records
            str_val = s.get("string", "")
            if len(str_val) >= 4:
                records.append(
                    RecoveredRecord(
                        record_id=f"text_{rec_counter}",
                        status=RecordStatus.PARTIAL,
                        byte_range=(s["offset"], s["offset"] + s["length"]),
                        fields={
                            "recovery_lane": "heuristic",
                            "type": "recovered_string",
                            "encoding": s["encoding"],
                            "text": str_val,
                            "confidence": 0.50,
                            "evidence": f"Printable {s['encoding']} string sequence",
                        },
                    )
                )
                rec_counter += 1
                if rec_counter > 50:
                    break

        # 2. Candidate-record recovery where stride was hypothesised
        heuristics = analysis_data.get("heuristics", [])
        stride_info = next((h for h in heuristics if h.get("heuristic") == "fixed_width_record_stride"), None)
        if stride_info:
            details = stride_info.get("details", {})
            stride = details.get("stride_bytes", 0)
            confidence = stride_info.get("confidence", 0.5)
            evidence = stride_info.get("evidence", "")

            if 16 <= stride <= 256:
                max_candidate_recs = min(20, len(data) // stride)
                for i in range(max_candidate_recs):
                    start = i * stride
                    end = start + stride
                    chunk = data[start:end]

                    # Decode candidate numeric fields
                    cand_fields: dict[str, Any] = {
                        "recovery_lane": "heuristic",
                        "type": "candidate_record",
                        "stride": stride,
                        "confidence": confidence,
                        "evidence": evidence,
                        "raw_hex": chunk[:32].hex(),
                    }
                    if len(chunk) >= 4:
                        u32_val = struct.unpack_from("<I", chunk, 0)[0]
                        cand_fields["candidate_uint32_0"] = u32_val
                    if len(chunk) >= 8:
                        cand_fields["candidate_uint32_4"] = struct.unpack_from("<I", chunk, 4)[0]

                    records.append(
                        RecoveredRecord(
                            record_id=f"stride_rec_{i+1}",
                            status=RecordStatus.PARTIAL,
                            byte_range=(start, end),
                            fields=cand_fields,
                        )
                    )

        return records

    @classmethod
    def calculate_coverage(
        cls,
        total_size: int,
        recovered_ranges: list[tuple[int, int]] | None = None,
        verified_ranges: list[tuple[int, int]] | None = None,
        heuristic_ranges: list[tuple[int, int]] | None = None,
    ) -> dict[str, Any]:
        """Calculates verified vs heuristic accounted ranges, unaccounted byte ranges, and percentages."""
        if total_size == 0:
            return {
                "total_bytes": 0,
                "recovered_bytes": 0,
                "verified_bytes": 0,
                "heuristic_bytes": 0,
                "unaccounted_bytes": 0,
                "coverage_pct": 100.0,
                "verified_coverage_pct": 100.0,
                "heuristic_coverage_pct": 0.0,
                "unaccounted_regions": [],
            }

        # Helper to merge overlapping / contiguous ranges
        def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
            sorted_ranges = sorted([r for r in ranges if r[1] > r[0]], key=lambda r: r[0])
            merged: list[tuple[int, int]] = []
            for start, end in sorted_ranges:
                start = max(0, min(total_size, start))
                end = max(0, min(total_size, end))
                if start >= end:
                    continue
                if not merged:
                    merged.append((start, end))
                else:
                    last_start, last_end = merged[-1]
                    if start <= last_end:
                        merged[-1] = (last_start, max(last_end, end))
                    else:
                        merged.append((start, end))
            return merged

        v_ranges = verified_ranges or []
        h_ranges = heuristic_ranges or []
        
        # If caller passed legacy recovered_ranges without split
        if not v_ranges and not h_ranges and recovered_ranges:
            v_ranges = recovered_ranges

        merged_verified = merge_ranges(v_ranges)
        merged_all = merge_ranges(v_ranges + h_ranges)

        verified_bytes = sum(end - start for start, end in merged_verified)
        total_recovered_bytes = sum(end - start for start, end in merged_all)
        heuristic_bytes = max(0, total_recovered_bytes - verified_bytes)
        unaccounted_bytes = max(0, total_size - total_recovered_bytes)

        coverage_pct = round((total_recovered_bytes / total_size) * 100.0, 2)
        verified_cov_pct = round((verified_bytes / total_size) * 100.0, 2)
        heuristic_cov_pct = round((heuristic_bytes / total_size) * 100.0, 2)

        # Build unaccounted regions
        unaccounted_regions: list[dict[str, int]] = []
        current_offset = 0
        for start, end in merged_all:
            if start > current_offset:
                unaccounted_regions.append({
                    "offset": current_offset,
                    "length": start - current_offset,
                })
            current_offset = max(current_offset, end)
        if current_offset < total_size:
            unaccounted_regions.append({
                "offset": current_offset,
                "length": total_size - current_offset,
            })

        return {
            "total_bytes": total_size,
            "recovered_bytes": total_recovered_bytes,
            "verified_bytes": verified_bytes,
            "heuristic_bytes": heuristic_bytes,
            "unaccounted_bytes": unaccounted_bytes,
            "coverage_pct": coverage_pct,
            "verified_coverage_pct": verified_cov_pct,
            "heuristic_coverage_pct": heuristic_cov_pct,
            "unaccounted_regions": unaccounted_regions[:50],  # bound count
        }
