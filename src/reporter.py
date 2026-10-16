"""Summary and report generator for salvage recovery pipeline.
Strictly conforms to OUTPUT-CONTRACT.md.
"""

from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from src.models import FileRecoveryResult, OutputStatus

class Reporter:
    """Manages writing per-file recovery JSON and aggregating the top-level report.json."""

    def __init__(self, output_dir: Path | str) -> None:
        self.output_dir = Path(output_dir)
        self.results: list[FileRecoveryResult] = []

    def add_result(self, result: FileRecoveryResult) -> None:
        self.results.append(result)

    def write_file_result(self, result: FileRecoveryResult) -> Path:
        """Writes the per-file recovery output."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        safe_base = Path(result.filename).name
        if safe_base == "report.json":
            safe_base = "report_input.json"
        out_name = f"{safe_base}.json"
        out_path = (self.output_dir / out_name).resolve()
        resolved_out_dir = self.output_dir.resolve()

        # Strict containment check preventing symlink escapes or directory traversal
        try:
            out_path.relative_to(resolved_out_dir)
        except ValueError:
            raise ValueError(f"Insecure output destination for file: {result.filename}")

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        return out_path

    def write_run_report(self) -> Path:
        """Writes the aggregated report.json complying with OUTPUT-CONTRACT.md."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        report_path = self.output_dir / "report.json"

        files_summary: list[dict[str, Any]] = []
        totals: dict[str, int] = {
            "ok": 0,
            "partial": 0,
            "unsupported": 0,
            "unrecognized": 0,
            "failed": 0,
        }

        formats_detected: dict[str, int] = {}
        for r in self.results:
            st = r.status.value if isinstance(r.status, OutputStatus) else str(r.status)
            totals[st] = totals.get(st, 0) + 1
            formats_detected[r.format_name] = formats_detected.get(r.format_name, 0) + 1
            files_summary.append({
                "file": r.filename,
                "format": r.format_name,
                "status": st,
                "records": len(r.records),
                "damage": len(r.damages),
                "records_recovered": len(r.records),
                "damage_count": len(r.damages),
                "is_valid_header": (st in ("ok", "partial")),
            })

        report_payload = {
            "tool_version": "1.0.0",
            "files": files_summary,
            "totals": totals,
            "summary": {
                "total_files_processed": len(self.results),
                "formats": formats_detected,
            },
        }

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)

        return report_path
