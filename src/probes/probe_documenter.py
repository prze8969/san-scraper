"""Synthesizes probe battery outcomes into formatted .probes.json and .probes.txt files and produces layout mapping."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from src.probes.probe_runner import ProbeResult
from src.models import FileRecoveryResult

class ProbeDocumenter:
    """Writes <file>.probes.json, <file>.probes.txt, and infers best-supported layout."""

    @classmethod
    def document_probes(
        cls,
        output_dir: Path | str,
        filename: str,
        data: bytes,
        probes: list[ProbeResult],
        recovery_result: FileRecoveryResult,
    ) -> tuple[Path, Path, list[dict[str, Any]]]:
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(filename).name

        # 1. Infer layout
        layout = cls._infer_layout(data, probes, recovery_result)

        # 2. Write <filename>.probes.json
        json_path = out_dir / f"{safe_name}.probes.json"
        json_payload = {
            "file": safe_name,
            "file_size": len(data),
            "probes_executed": len(probes),
            "probes_matched": len([p for p in probes if p.result == "match"]),
            "layout": layout,
            "probes": [p.to_dict() for p in probes],
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2)

        # 3. Write <filename>.probes.txt
        txt_path = out_dir / f"{safe_name}.probes.txt"
        cls._write_human_text_report(txt_path, safe_name, len(data), probes, layout, recovery_result)

        return json_path, txt_path, layout

    @classmethod
    def _infer_layout(
        cls,
        data: bytes,
        probes: list[ProbeResult],
        recovery_result: FileRecoveryResult,
    ) -> list[dict[str, Any]]:
        """Infers best-supported interpretation of header, body, checksum, footer regions with confidence and verification status."""
        total_size = len(data)
        if total_size == 0:
            return [{
                "region": "empty",
                "offset_range": [0, 0],
                "role": "empty_stream",
                "status": "verified",
                "confidence": 1.0,
            }]

        layout: list[dict[str, Any]] = []

        # Header region
        hdr_len = 0
        hdr_status = "hypothesized"
        hdr_conf = 0.5
        hdr_role = "header"

        if recovery_result.is_valid_header:
            hdr_status = "verified"
            hdr_conf = 1.0
            # Common header sizes for supported formats
            if recovery_result.format_name == "LIBRA-98":
                hdr_len = 32
            elif recovery_result.format_name == "LABLOG":
                hdr_len = 24
            elif recovery_result.format_name == "VAULT":
                hdr_len = 32
            elif recovery_result.format_name == "PAK":
                hdr_len = 12
            elif recovery_result.format_name == "WKS":
                hdr_len = 6
            else:
                hdr_len = min(32, total_size)
            hdr_role = f"{recovery_result.format_name}_header"
        else:
            # Check if any signature probe matched at offset 0 or non-zero
            sig_match = next((p for p in probes if p.family == "signatures" and p.result == "match" and p.byte_range[0] == 0), None)
            if sig_match:
                hdr_len = max(4, sig_match.byte_range[1])
                hdr_conf = sig_match.score
                hdr_role = f"{sig_match.parameters.get('format', 'unknown')}_signature_block"
            else:
                hdr_len = min(16, total_size)
                hdr_conf = 0.3
                hdr_role = "candidate_header_preamble"

        hdr_end = min(total_size, max(4, hdr_len))
        layout.append({
            "region": "header",
            "offset_range": [0, hdr_end],
            "role": hdr_role,
            "status": hdr_status,
            "confidence": round(hdr_conf, 2),
        })

        # Footer / Checksum region check
        footer_start = total_size
        footer_role = "unspecified"
        footer_status = "hypothesized"
        footer_conf = 0.0

        # Check footer probes
        footer_match = next((p for p in probes if p.family == "footer" and p.result == "match"), None)
        chk_match = next((p for p in probes if p.family == "checksums" and p.result == "match" and "trailer" in p.parameters.get("range", "")), None)

        if footer_match:
            footer_start = footer_match.byte_range[0]
            footer_role = f"trailer_{footer_match.parameters.get('marker', 'terminator')}"
            footer_status = "hypothesized"
            footer_conf = footer_match.score
        elif chk_match and total_size >= 4:
            footer_start = total_size - 4
            footer_role = f"stored_trailer_{chk_match.parameters.get('algorithm', 'checksum')}"
            footer_status = "hypothesized"
            footer_conf = chk_match.score

        # Body region
        body_end = footer_start if footer_start > hdr_end else total_size
        body_len = max(0, body_end - hdr_end)

        body_status = "verified" if (recovery_result.is_valid_header and len(recovery_result.recovered_records) > 0) else "hypothesized"
        body_conf = 1.0 if body_status == "verified" else 0.6
        body_role = f"{recovery_result.format_name}_records_body" if recovery_result.is_valid_header else "content_payload"

        # Check if stride probe matched with stride >= 4 and confidence >= 0.6
        stride_match = next((p for p in probes if p.family == "structure" and p.result == "match" and "stride" in p.probe_id), None)
        if stride_match and body_status != "verified":
            stride_bytes = stride_match.parameters.get("stride_bytes", 0)
            if stride_bytes >= 4 and stride_match.score >= 0.60:
                body_role = f"fixed_stride_records_body (stride={stride_bytes}B)"
                body_conf = stride_match.score

        if body_len > 0:
            layout.append({
                "region": "body",
                "offset_range": [hdr_end, body_end],
                "role": body_role,
                "status": body_status,
                "confidence": round(body_conf, 2),
            })

        # Add footer region if detected
        if footer_start < total_size:
            layout.append({
                "region": "footer",
                "offset_range": [footer_start, total_size],
                "role": footer_role,
                "status": footer_status,
                "confidence": round(footer_conf, 2),
            })

        return layout

    @classmethod
    def _write_human_text_report(
        cls,
        path: Path,
        filename: str,
        size: int,
        probes: list[ProbeResult],
        layout: list[dict[str, Any]],
        recovery_result: FileRecoveryResult,
    ) -> None:
        lines: list[str] = []
        lines.append(f"================================================================================")
        lines.append(f" FORENSIC PROBE BATTERY REPORT: {filename}")
        lines.append(f" File Size: {size} bytes | Format: {recovery_result.format_name} (valid_header={recovery_result.is_valid_header})")
        lines.append(f" Total Probes Executed: {len(probes)} | Matched: {len([p for p in probes if p.result == 'match'])}")
        lines.append(f"================================================================================")
        lines.append("")

        # 1. Probe Counts per Family
        lines.append("--- PROBE FAMILIES SUMMARY ---")
        family_counts: dict[str, dict[str, int]] = {}
        for p in probes:
            if p.family not in family_counts:
                family_counts[p.family] = {"total": 0, "match": 0, "no_match": 0, "error": 0}
            family_counts[p.family]["total"] += 1
            family_counts[p.family][p.result] += 1

        for fam, counts in sorted(family_counts.items()):
            lines.append(
                f" - {fam:<15}: {counts['match']:>3} matches / {counts['total']:>3} executed "
                f"({counts['no_match']} non-matches, {counts['error']} errors)"
            )
        lines.append("")

        # 2. Inferred Layout
        lines.append("--- INFERRED BYTE LAYOUT ---")
        for reg in layout:
            rng = f"[{reg['offset_range'][0]}:{reg['offset_range'][1]}]"
            lines.append(
                f" - {reg['region'].upper():<8} {rng:<16} {reg['role']:<35} "
                f"conf={reg['confidence']:.2f} ({reg['status']})"
            )
        lines.append("")

        # 3. Matches with Evidence
        lines.append("--- MATCHING PROBES WITH EVIDENCE ---")
        matches = [p for p in probes if p.result == "match"]
        if matches:
            for m in sorted(matches, key=lambda x: -x.score):
                lines.append(f" [{m.family.upper()}] id={m.probe_id} score={m.score:.2f} range={m.byte_range}")
                lines.append(f"   Evidence: {m.evidence}")
        else:
            lines.append(" (No probe matches identified)")
        lines.append("")

        # 4. Short list of Non-Matching Families (families with 0 matches)
        lines.append("--- FAMILIES WITH ZERO MATCHES ---")
        zero_match_fams = [fam for fam, c in family_counts.items() if c["match"] == 0]
        if zero_match_fams:
            for fam in sorted(zero_match_fams):
                lines.append(f" - {fam}: All {family_counts[fam]['total']} probes returned no_match")
        else:
            lines.append(" (All families produced at least one match)")
        lines.append("")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
