# Project Tracker: PS 02 - Salvage (`san-scraper`)

**Last Updated:** 2026-10-16  
**Primary Deliverables:** Offline CLI (`./salvage <input_dir> <output_dir>`), [`FORMAT-SPEC.md`](file:///e:/san%20scarper/san-scraper/FORMAT-SPEC.md), [`FIELD-LOG.md`](file:///e:/san%20scarper/san-scraper/FIELD-LOG.md), [`PROJECT-TRACKER.md`](file:///e:/san%20scarper/san-scraper/PROJECT-TRACKER.md).

---

## 1. Executive Status Board

| Milestone / Requirement | Target Description | Current Status | Test Coverage |
| :--- | :--- | :---: | :---: |
| **CLI & Execution Contract** | `./salvage <in> <out>`, zero network, offline stdlib, Docker, exit code 0 | **COMPLETED** | 100% Passing (`test_cli.py`, `test_engine.py`) |
| **Defensive I/O Primitives** | Bounds checking, 32MB max alloc, slice unpack, safe skip | **COMPLETED** | 100% Passing (`test_reader.py`) |
| **Safety & Security Audits** | Path traversal, symlink escape, bounded RLE decompress bomb | **COMPLETED** | 100% Passing (`test_security.py`, `test_robustness.py`) |
| **Participant Kit Integration**| `Genesis_Track3_PS2_Sample_Files-main` (30 samples, 7 expected outputs) | **COMPLETED** | 30/30 samples processed cleanly |
| **Output Contract Alignment** | Strict schema conformance to `OUTPUT-CONTRACT.md` | **COMPLETED** | 100% Passing (`report.json` + per-file JSON) |
| **LIBRA-98 (`s01`..`s04.dat`)** | Magic `LB98`, branch ID, ISO dates, books records, damages | **COMPLETED** | **100% Match** (`s01.dat.json`, `s04.dat.json`) |
| **LABLOG (`s05`..`s07.dat`)** | Magic `LLOG`, sample interval, channels, UTC start, events | **COMPLETED** | **100% Match** (`s05.dat.json`) |
| **VAULT (`s08`..`s10.dat`)** | Magic `VLT1`, rolling XOR cipher, PackBits RLE, sha256 | **COMPLETED** | **100% Match** (`s08.dat.json`) |
| **Lotus 1-2-3 (`s11`..`s13.wks`)** | Real-world legacy spreadsheet format (`BOF`, cell opcodes, formulas) | **COMPLETED** | **100% Match** (`s11.wks.json`) |
| **WordPerfect (`s14`..`s15.wpd`)** | `\xFFWPC` header, paragraphs, page breaks | **COMPLETED** | Handled per contract |
| **Bravo (`s16`..`s17.bravo`)** | 1970s Xerox Alto research lab editor, CR paragraphs | **COMPLETED** | Handled per contract |
| **CVT (`s18`..`s19.cvt`)** | Commodore 64 GEOS convert disk format (seq/vlir, scraps, PETSCII) | **COMPLETED** | **100% Match** (`s18.cvt.json`) |
| **EBCDIC-DUMP (`s20`..`s22.000`)**| University mainframe tape dump (EBCDIC CP037 student records, COMP-3) | **COMPLETED** | **100% Match** (`s20.000.json`) |
| **Doom WAD (`s23.wad`)** | `PWAD`/`IWAD` archive (lumps: name, offset, size, sha256) | **COMPLETED** | Handled per contract |
| **Quake PAK (`s24.pak`)** | `PACK` archive (files: name, offset, size, sha256) | **COMPLETED** | Handled per contract |
| **UNKNOWN / Hostile Fallback** | `s25`..`s30` (random binary, empty, tiny, damaged, png-like) | **COMPLETED** | Defensive non-crashing reporting (status ok / partial / unrecognized) |

---

## 2. Format Matrix & Verification Results

| File(s) | Format | Identified Signature | Calibration Result |
| :--- | :--- | :--- | :--- |
| `s01.dat` - `s04.dat` | **LIBRA-98** | `4C 42 39 38` (`LB98`) | **100% Match** with `s01.dat.json` & `s04.dat.json` |
| `s05.dat` - `s07.dat` | **LABLOG** | `4C 4C 4F 47` (`LLOG`) | **100% Match** with `s05.dat.json` |
| `s08.dat` - `s10.dat` | **VAULT** | `56 4C 54 31` (`VLT1`) | **100% Match** with `s08.dat.json` |
| `s11.wks` - `s13.wks` | **WKS** | `00 00 02 00 04 04` | **100% Match** with `s11.wks.json` |
| `s14.wpd` - `s15.wpd` | **WPD** | `FF 57 50 43` (`\xFFWPC`) | Conforming to contract |
| `s16.bravo` - `s17.bravo`| **BRAVO** | Plain text + format runs | Conforming to contract |
| `s18.cvt` - `s19.cvt` | **CVT** | `83 00 00` + GEOS header | **100% Match** with `s18.cvt.json` |
| `s20.000` - `s22.000` | **EBCDIC-DUMP** | Block records in EBCDIC CP037 | **100% Match** with `s20.000.json` |
| `s23.wad` | **WAD** | `50 57 41 44` (`PWAD`) | Conforming to contract |
| `s24.pak` | **PAK** | `50 41 43 4B` (`PACK`) | Conforming to contract |
| `s25_random.bin` | **UNKNOWN** | Random binary stream | Emits status `unrecognized` |
| `s26_empty.dat` | **UNKNOWN** | 0-byte empty file | Emits status `ok`, format `UNKNOWN` |
| `s27_notes.txt` | **UNKNOWN** | Plain text notes | Emits status `unrecognized` |
| `s28_tiny.dat` | **UNKNOWN** | 1-byte file | Emits status `unrecognized` |
| `s29_almost_libra.dat`| **LIBRA-98** | Truncated 7-byte header | Emits status `failed`, `truncated` damage |
| `s30_png_like.dat` | **UNKNOWN** | PNG header | Emits status `unrecognized` |

---

## 3. Completed Phases Summary

- **Phase 1: Participant Kit Ingestion & Contract Alignment** -> **100% Complete**
- **Phase 2: Reverse Engineering of All Formats** -> **100% Complete**
- **Phase 3: Golden Reference Calibration (7/7 Match)** -> **100% Complete**
- **Phase 4: Full Test Suite Verification (55/55 Passing)** -> **100% Complete**
- **Phase 5: Technical Documentation & Specifications** -> **100% Complete**
