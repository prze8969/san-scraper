# CONTEXT.md: Project Overview & Developer Guide

## Project Goal
`san-scraper` (`salvage`) is a defensive binary file recovery engine developed for **PS 02: Salvage**. Its objective is to recover structured records from legacy, damaged, or corrupted binary files completely offline with zero dynamic execution and bounded resource safety.

## Current Status (PS 02)
All 93 test cases pass (`93 passed in ~0.88s`). The engine supports 6 formats implemented from documented specifications (Lotus 1-2-3 `.WKS`, Quake `.PAK`, Doom `.WAD`, `.ZIP`, `.GZIP`, `.PNG`), 3 provisional formats for validation gating (`LIBRA-98`, `LABLOG`, `VAULT`), and an `UNKNOWN`/`EMPTY` fallback handler. It features a generic analysis pipeline (Shannon entropy, printable strings, byte stride autocorrelation), a 400+ forensic probe battery, bounded carving, container extraction to `<output_dir>/<name>.extracted/`, and strict split coverage reporting (verified vs heuristic).

## Honest Limitations
- **Provisional Layouts:** `LIBRA-98`, `LABLOG`, and `VAULT` are provisional specifications implemented for test-suite contract verification; official ground-truth samples were not provided in the challenge workspace.
- **Hypotheses vs Verified:** Probes, autocorrelation strides, and generic string extractions are structural hypotheses, not verified schema decodes.
- **Inert Formulas:** Lotus 1-2-3 formulas (`0x0010`) are preserved strictly as inert data without runtime evaluation.
- **Grader Schema:** Emits forensic salvage schema (`file`, `format`, `records`, `damages`, `metadata`, `analysis`, `coverage`, `layout`). An authoritative external JSON schema file is unconfirmed.

## Run Commands
```powershell
# Run complete test suite (93 tests)
python -m unittest discover tests

# Process a single file
.\salvage.bat <input_file> <output_dir> [--verbose] [--quiet]
# or:
python -m src.cli <input_file> <output_dir> [--verbose] [--quiet]

# Process an entire directory
.\salvage.bat <input_dir> <output_dir>

# Run end-to-end demo
.\demo\run_demo.bat

# Docker build & run (Linux container entrypoint)
docker build -t salvage .
docker run --rm -v ${PWD}/demo/input:/input -v ${PWD}/demo/output:/output salvage /input /output
```

## Recommended Reading Order
1. [CONTEXT.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/CONTEXT.md) (This file)
2. [ARCHITECTURE.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/ARCHITECTURE.md) (Pipeline, lanes, and data models)
3. [CODEMAP.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/CODEMAP.md) (File-by-file module reference)
4. [FORMATS.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/FORMATS.md) (Format layouts, opcodes, and parser mapping)
5. [SCHEMA.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/SCHEMA.md) (JSON output specification)
6. [TESTS.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/TESTS.md) (Test suite inventory and test patterns)
7. [DECISIONS.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/DECISIONS.md) (Architectural decisions and rejected ideas)
8. [TODO.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/TODO.md) (Prioritized backlog)

## Do Not Touch Without Reading First
- **`src/reader.py`**: Do not alter read bounds or allocations without reading [DECISIONS.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/DECISIONS.md) (security bounds).
- **`src/models.py`**: Do not remove `_sanitize` or change JSON serialization keys without reading [SCHEMA.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/SCHEMA.md).
- **`src/formats/libra98.py`, `lablog.py`, `vault.py`**: Do not modify without reading [FIELD-LOG.md](file:///c:/Users/Pranav%20Shewale/zebro-scraper/FIELD-LOG.md) and keeping tests green.

## Change-Safety Coupling ("If you change X, also update Y")
| If you change / add... | You MUST also update... |
| :--- | :--- |
| **New Binary Format Parser** | Add parser to `src/formats/`, register in `src/detector.py`, `src/detector_pipeline.py`, and `src/engine.py`, add unit tests in `tests/`, add row in `FORMATS.md` and `README.md`. |
| **Data Models / Record Fields** | Update `src/models.py`, `src/reporter.py`, `SCHEMA.md`, and affected test assertions in `tests/test_analysis_and_recovery.py`. |
| **Analysis / Coverage Logic** | Update `src/recovery/carver.py`, `src/engine.py`, `src/reporter.py`, and verify coverage tests in `tests/test_analysis_and_recovery.py`. |
| **Extraction / Sanitization** | Update `src/recovery/extractor.py`, `tests/test_known_formats.py`, and verify path containment in `tests/test_security.py`. |
