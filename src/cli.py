"""Command-line interface entry point for salvage (san-scraper)."""

from __future__ import annotations
import sys
import argparse
from pathlib import Path
from src.engine import SalvageEngine
from src.reporter import Reporter

def run_salvage(
    input_path: str,
    output_dir: str,
    verbose: bool = False,
    quiet: bool = False,
) -> int:
    try:
        in_path = Path(input_path)
        out_path = Path(output_dir)

        out_path.mkdir(parents=True, exist_ok=True)
        reporter = Reporter(out_path)

        if not in_path.exists():
            sys.stderr.write(f"Warning: Path does not exist: {input_path}\n")
            reporter.write_run_report()
            return 0

        engine = SalvageEngine(output_dir=out_path)

        # Collect files to process (single file or entire directory, non-recursive, skip subdirectories)
        files_to_process: list[Path] = []
        if in_path.is_file():
            files_to_process.append(in_path)
        elif in_path.is_dir():
            for item in sorted(in_path.iterdir()):
                # Skip subdirectories (non-recursive)
                if item.is_file():
                    files_to_process.append(item)
        else:
            sys.stderr.write(f"Warning: Path is neither a regular file nor a directory: {input_path}\n")
            reporter.write_run_report()
            return 0

        # Process all selected files with per-file exception containment
        for item in files_to_process:
            try:
                res = engine.process_file(item, output_dir=out_path)
            except Exception as e:
                # Catch internal error and emit status failed with damage entry
                from src.models import FileRecoveryResult, DamageBlock, DamageType
                file_size = 0
                try:
                    file_size = item.stat().st_size
                except Exception:
                    pass
                res = FileRecoveryResult(
                    filename=item.name,
                    format_name="UNKNOWN",
                    file_size=file_size,
                    is_valid_header=False,
                    total_records=0,
                    damages=[
                        DamageBlock(
                            offset=0,
                            length=file_size,
                            damage_type=DamageType.INVALID_HEADER,
                            description=f"Internal processing failure: {str(e)}",
                        )
                    ],
                )

            reporter.add_result(res)
            reporter.write_file_result(res)

            if not quiet:
                Reporter.print_file_terminal_report(res, verbose=verbose)

        # Write aggregated run report
        reporter.write_run_report()

        if not quiet and len(files_to_process) > 1:
            Reporter.print_batch_summary(reporter.results)

    except Exception as fatal_e:
        sys.stderr.write(f"Warning: Salvage execution error: {str(fatal_e)}\n")
        try:
            out_p = Path(output_dir)
            out_p.mkdir(parents=True, exist_ok=True)
            rep_file = out_p / "report.json"
            if not rep_file.exists():
                rep_file.write_text('{"tool_version":"salvage-ps02-v1.0","files":[],"totals":{"ok":0,"partial":0,"unsupported":0,"unrecognized":0,"failed":0}}', encoding="utf-8")
        except Exception:
            pass

    return 0

def main() -> None:
    parser = argparse.ArgumentParser(
        description="salvage: Defensive binary file analysis and data recovery"
    )
    parser.add_argument("path", help="Path to a single file OR an input directory")
    parser.add_argument("output_dir", help="Path to the output directory")
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Print the full probe table"
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true", help="Suppress terminal output"
    )

    args = parser.parse_args()
    exit_code = run_salvage(
        args.path,
        args.output_dir,
        verbose=args.verbose,
        quiet=args.quiet,
    )
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
