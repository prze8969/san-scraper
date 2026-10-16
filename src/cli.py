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
    in_path = Path(input_path)
    out_path = Path(output_dir)

    if not in_path.exists():
        sys.stderr.write(f"Error: Path does not exist: {input_path}\n")
        return 1

    out_path.mkdir(parents=True, exist_ok=True)

    engine = SalvageEngine(output_dir=out_path)
    reporter = Reporter(out_path)

    # Collect files to process (single file or entire directory)
    files_to_process: list[Path] = []
    if in_path.is_file():
        files_to_process.append(in_path)
    elif in_path.is_dir():
        files_to_process.extend(sorted([f for f in in_path.iterdir() if f.is_file()]))
    else:
        sys.stderr.write(f"Error: Path is neither a regular file nor a directory: {input_path}\n")
        return 1

    # Process all selected files
    for item in files_to_process:
        res = engine.process_file(item, output_dir=out_path)
        reporter.add_result(res)
        reporter.write_file_result(res)

        # Print per-file terminal report unless quiet mode
        if not quiet:
            Reporter.print_file_terminal_report(res, verbose=verbose)

    # Write aggregated run report
    reporter.write_run_report()

    # Print batch summary if more than 1 file and not quiet
    if not quiet and len(files_to_process) > 1:
        Reporter.print_batch_summary(reporter.results)

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
