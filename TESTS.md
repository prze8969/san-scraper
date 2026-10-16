# TESTS.md: Test Suite Inventory & Coverage

## Test Suite Execution Command
```powershell
python -m unittest discover tests
```

### Latest Verified Run Result
```text
Ran 93 tests in 0.878s

OK
```

---

## Test Inventory by File

| Test File | Tests | Label Type | Scope & Scenarios Covered |
| :--- | :--- | :--- | :--- |
| `tests/test_known_formats.py` | 14 | **Independent + Seeded Fuzz** | Hand-assembled byte fixtures citing authoritative specs: Doom WAD (IWAD, zero-length markers, truncated dir, out-of-bounds lump); ZIP (stored, deflate, missing central dir, bad CRC32, path traversal, decompression bomb); GZIP (valid stream, altered CRC trailer, truncated stream); PNG (valid chunks, corrupted CRC chunk isolation); container extraction to disk; seeded fuzz tests (no crash/hang). |
| `tests/test_pak.py` | 9 | Independent & Self-consistency | Quake PAK synthetic construction; valid archive, empty files, multi-file archive, header corruption, truncated directory, path traversal sanitization, and damage block reporting. |
| `tests/test_wks.py` | 8 | Independent & Self-consistency | Lotus 1-2-3 R1A synthetic fixtures; BOF/EOF framing, BLANK, INTEGER, NUMBER, LABEL, FORMULA cells, truncated records, malformed header, and grid mapping verification. |
| `tests/test_libra98.py` | 6 | Independent & Self-consistency | LIBRA-98 provisional validation gate; valid header, checksum checking, corrupted header, truncated records, variable records, and CRC16 record errors. |
| `tests/test_lablog.py` | 5 | Independent & Self-consistency | LABLOG provisional telemetry format; valid blocks, damaged block CRC32 isolation, resynchronization past corrupted block, and session header parsing. |
| `tests/test_vault.py` | 7 | Independent & Self-consistency | VAULT provisional format; PackBits RLE compression, XOR 1-byte masking, index bounds checking, decompression bomb mitigation (16 MB cap), and truncated archive. |
| `tests/test_reader.py` | 6 | Independent | `BoundedBinaryReader` primitive operations; byte slices, out-of-bounds seeks, truncated reads, unsigned/signed integer unpacking, and allocation caps. |
| `tests/test_analysis_and_recovery.py` | 8 | Independent | `FileAnalyzer` statistical profiling (entropy, string extraction, byte frequency); whole-buffer signature scanning; candidate-record heuristic extraction; disjoint byte coverage split (verified vs heuristic). |
| `tests/test_probes.py` | 7 | Independent | `ProbeRunner` 400+ forensic probe executions; signatures, headers, footers, structural strides, and layout inference mapping (`ProbeDocumenter`). |
| `tests/test_security.py` | 10 | Independent | Path traversal resistance (`../../`), Windows absolute drive letters (`C:\`), decompression bomb memory exhaustion defenses, output directory confinement (`relative_to` containment). |
| `tests/test_robustness.py` | 9 | Independent & Fuzzing | Zero-length files, 1-byte files, random noise files, truncated headers, corrupted offsets, and execution stability under malformed inputs. |
| `tests/test_engine.py` | 3 | Integration | `SalvageEngine` top-level orchestration; file loading, pipeline candidate detection, parser dispatch, and carved output handling. |
| `tests/test_cli.py` | 1 | Integration | CLI argument parsing, single-file and directory dispatch, `--verbose` and `--quiet` flags, and exit code verification. |

**Total:** 13 test files, 93 passing unit & integration tests.
