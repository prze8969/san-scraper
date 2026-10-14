"""Command-line interface entry point for salvage (san-scraper)."""

from __future__ import annotations
import sys
from pathlib import Path
from src.engine import SalvageEngine
from src.reporter import Reporter

def run_salvage(input_dir: str, output_dir: str) -> int:
    in_path = Path(input_dir)
    out_path = Path(output_dir)

    if not in_path.exists() or not in_path.is_dir():
        sys.stderr.write(f"Error: Input directory does not exist or is not a directory: {input_dir}\n")
        return 1

    out_path.mkdir(parents=True, exist_ok=True)

    engine = SalvageEngine()
    reporter = Reporter(out_path)

    # Process all regular files in input directory
    for item in sorted(in_path.iterdir()):
        if item.is_file():
            res = engine.process_file(item)
            reporter.add_result(res)
            reporter.write_file_result(res)

    reporter.write_run_report()
    return 0

def main() -> None:
    if len(sys.argv) != 3:
        sys.stderr.write("Usage: ./salvage <input_dir> <output_dir>\n")
        sys.exit(1)

    input_dir = sys.argv[1]
    output_dir = sys.argv[2]
    exit_code = run_salvage(input_dir, output_dir)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
