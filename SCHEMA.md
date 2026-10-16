# SCHEMA.md: Output JSON Schema & Examples

The engine produces two categories of JSON output:
1. `<output_dir>/<filename>.json`: Detailed forensic salvage record for each individual input file.
2. `<output_dir>/report.json`: Aggregated summary across all files in the batch run.

---

## 1. Per-File Output Structure (`<filename>.json`)

Emitted by `FileRecoveryResult.to_dict()` in `src/models.py`.

```json
{
  "file": "05_valid.wks",
  "format": "WKS",
  "file_size": 85,
  "is_valid_header": true,
  "total_records_recovered": 6,
  "total_declared_records": 6,
  "records": [
    {
      "id": 1,
      "status": "complete",
      "byte_range": [15, 26],
      "data": {
        "opcode": 13,
        "payload_len": 7,
        "record_type": "INTEGER",
        "col": 1,
        "row": 2,
        "value": 42
      }
    }
  ],
  "damages": [
    {
      "offset": 45,
      "length": 10,
      "type": "checksum_mismatch",
      "description": "CRC32 mismatch: declared 0x12345678, computed 0x87654321"
    }
  ],
  "metadata": {
    "saw_bof": true,
    "saw_eof": true,
    "version_code": "0x0404",
    "grid": {
      "R2C1": { "type": "INTEGER", "value": 42 },
      "R2C2": { "type": "NUMBER", "value": 98.6 }
    }
  },
  "analysis": {
    "size": 85,
    "sha256": "4b68...",
    "entropy": 4.12,
    "printable_strings": [
      { "offset": 47, "length": 10, "encoding": "ascii", "string": "REVENUE_Q1" }
    ],
    "signatures": [
      { "format": "WKS", "offset": 0, "confidence": 1.0, "description": "Lotus 1-2-3 BOF record" }
    ],
    "heuristics": []
  },
  "detection_candidates": [
    {
      "format": "WKS",
      "confidence": 1.0,
      "method": "exact_magic_offset_0",
      "offset": 0,
      "evidence": "Exact magic match at offset 0: Lotus 1-2-3 BOF record"
    }
  ],
  "carved_objects": [],
  "coverage": {
    "total_bytes": 85,
    "recovered_bytes": 79,
    "verified_bytes": 79,
    "heuristic_bytes": 0,
    "unaccounted_bytes": 6,
    "coverage_pct": 92.94,
    "verified_coverage_pct": 92.94,
    "heuristic_coverage_pct": 0.0,
    "unaccounted_regions": [
      { "offset": 0, "length": 6 }
    ]
  },
  "probe_summary": {
    "total_probes": 447,
    "matched_probes": 102
  },
  "layout": [
    { "region": "header", "offset_range": [0, 6], "role": "WKS_header", "status": "verified", "confidence": 1.0 },
    { "region": "body", "offset_range": [6, 81], "role": "WKS_records_body", "status": "verified", "confidence": 1.0 },
    { "region": "footer", "offset_range": [81, 85], "role": "trailer_WKS_EOF", "status": "hypothesized", "confidence": 0.9 }
  ]
}
```

---

## 2. Run-Level Summary Structure (`report.json`)

Emitted by `Reporter.write_batch_summary()` in `src/reporter.py`.

```json
{
  "total_files_processed": 14,
  "total_records_recovered": 97,
  "total_verified_records": 32,
  "total_heuristic_records": 65,
  "total_damaged_blocks": 6,
  "formats": {
    "LIBRA-98": 1,
    "LABLOG": 2,
    "VAULT": 1,
    "PAK": 3,
    "WKS": 1,
    "UNKNOWN": 2,
    "PNG": 1,
    "WAD": 1,
    "ZIP": 1,
    "GZIP": 1
  },
  "files": [
    {
      "file": "05_valid.wks",
      "format": "WKS",
      "confidence": 1.0,
      "total_records": 6,
      "verified_records": 6,
      "heuristic_records": 0,
      "carved_objects": 0,
      "total_coverage_pct": 92.94,
      "verified_coverage_pct": 92.94,
      "heuristic_coverage_pct": 0.0,
      "damage_blocks": 0
    }
  ]
}
```

---

## 3. Heuristic / Unknown Record Example (`10_unknown_records.dat.json`)

When a file format is UNKNOWN or unrecognized, records are emitted with `recovery_lane: "heuristic"` and verified coverage is strictly 0%:

```json
{
  "id": "text_1",
  "status": "partial",
  "byte_range": [0, 4],
  "data": {
    "type": "recovered_string",
    "encoding": "ascii",
    "text": "EVNT",
    "recovery_lane": "heuristic"
  }
}
```
