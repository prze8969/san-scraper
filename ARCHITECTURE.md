# ARCHITECTURE.md: Pipeline Design & Data Models

## Text Pipeline Diagram

```text
[ CLI Input: file or dir ]
         |
         v
[ src.cli: run_salvage ]
         |
         v
[ src.engine: SalvageEngine.process_file / process_bytes ]
         |
         +---> 1. FileAnalyzer (src/analysis/file_analyzer.py)
         |        - SHA-256, Shannon entropy, byte-distribution, printable strings,
         |          autocorrelation stride, zero/pattern gaps, signatures scan.
         |
         +---> 2. PipelineDetector (src/detector_pipeline.py & src/detector.py)
         |        - Multi-tier detection: offset 0 magic, whole-buffer signature,
         |          extension heuristic. Emits ranked DetectionCandidates.
         |
         +---> 3. Parser Execution (src/formats/*)
         |        - BaseParser interface via BoundedBinaryReader.
         |        - Defensive parsing, checksum check, damage isolation.
         |        - Emits FileRecoveryResult with verified RecoveredRecords & DamageBlocks.
         |
         +---> 4. Container Extraction (src/recovery/extractor.py)
         |        - If archive (PAK, WAD, ZIP, GZIP), writes sanitized files to:
         |          <output_dir>/<name>.extracted/
         |
         +---> 5. Bounded Carver (src/recovery/carver.py)
         |        - Searches signatures for PNG, ZIP, JPEG embedded in raw buffers.
         |        - Carves bounded slices to <output_dir>/<name>.carved/
         |
         +---> 6. Generic Recovery & Split Coverage (src/recovery/carver.py)
         |        - If UNKNOWN or 0 verified records: extracts printable strings & stride records.
         |        - Computes disjoint byte coverage:
         |            * Verified Coverage: parsed records by format parser.
         |            * Heuristic Coverage: strings, carved slices, stride records.
         |            * Unaccounted Regions: residual unexplained byte ranges.
         |
         +---> 7. Forensic Probe Battery (src/probes/probe_runner.py & probe_documenter.py)
         |        - Runs 400+ probes across families (signatures, header, footer, etc.)
         |        - Documents probe outcomes to <output_dir>/<name>.probes.txt and .json
         |        - Infers file layout map (HEADER, BODY, FOOTER)
         |
         v
[ src.reporter: Reporter ]
         +---> Emits <output_dir>/<name>.json (per-file recovery record)
         +---> Emits <output_dir>/report.json (run-level summary)
         +---> Terminal Report: Layout map, record table, cell grid, coverage, damage blocks.
```

## Data Models (`src/models.py`)

- **`RecordStatus` (Enum):** `COMPLETE`, `PARTIAL`, `CORRUPTED`, `UNRECOVERABLE`.
- **`DamageType` (Enum):** `TRUNCATION`, `CHECKSUM_MISMATCH`, `INVALID_HEADER`, `CORRUPT_RECORD`, `MALFORMED_OFFSET`, `UNKNOWN_SIGNATURE`, `DECOMPRESSION_ERROR`.
- **`DamageBlock`:** `offset: int`, `length: int`, `damage_type: DamageType`, `description: str`.
- **`RecoveredRecord`:**
  - `record_id: Any`
  - `status: RecordStatus`
  - `byte_range: tuple[int, int]`
  - `fields: dict[str, Any]` (holds parsed attributes; bytes safely sanitized for JSON)
  - `errors: list[str]`
- **`FileRecoveryResult`:**
  - `filename: str`, `format_name: str`, `file_size: int`, `is_valid_header: bool`, `total_records: int`
  - `recovered_records: list[RecoveredRecord]`
  - `damages: list[DamageBlock]`
  - `metadata: dict[str, Any]` (e.g. `grid` for spreadsheets, version codes)
  - `analysis: dict[str, Any]` (entropy, strings, signatures)
  - `detection_candidates: list[dict[str, Any]]`
  - `carved_objects: list[dict[str, Any]]`
  - `coverage: dict[str, Any]` (`verified_coverage_pct`, `heuristic_coverage_pct`, `unaccounted_regions`)
  - `probe_summary: dict[str, Any]` (`total_probes`, `matched_probes`)
  - `layout: list[dict[str, Any]]` (regions with role, status, and confidence)

## The Two Lanes: Verified vs Heuristic

To prevent false confidence and fabricated claims, the recovery pipeline strictly separates coverage and records into two independent lanes:

1. **Verified Lane:**
   - Populated **only** by an authoritative format parser (`WKS`, `PAK`, `WAD`, `ZIP`, `GZIP`, `PNG`, `LIBRA-98`, `LABLOG`, `VAULT`).
   - Every byte range corresponds directly to an understood structural element (header, directory, chunk, cell record).
   - Random noise or unknown files have **0% verified coverage**.

2. **Heuristic Lane:**
   - Populated by generic probes, printable string scanner, autocorrelation record strides, and carved embedded objects.
   - Identified in records by `recovery_lane: "heuristic"`.
   - Never marked as verified; reported with confidence ratings (< 1.0) and labelled as structural hypotheses.
