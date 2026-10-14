# FIELD-LOG: Evidence, Hypotheses, and Research Notes

This document maintains an evidence-driven log of binary format reverse-engineering, format discovery, structural hypotheses, and validation outcomes for **PS 02: Salvage** (Project: `san-scraper`).

## Evidence Categories

Every format specification or field definition belongs to one of three categories:
- **Verified:** Established by authoritative challenge documentation, official vendor specifications, or verified sample files.
- **Hypothesized:** Plausible structure inferred from domain conventions or provisional contracts, awaiting authoritative validation.
- **Unknown:** Insufficient evidence exists; structure not yet established.

---

## 1. High-Level Requirements & Execution Contract

### Verified:
- **Invocation CLI:** `./salvage <input_dir> <output_dir>`
- **Offline Operation:** Zero external network requests, zero dynamic downloads during run.
- **Failure Tolerance:** Processing must not crash on malformed inputs, truncated files, out-of-bounds offsets, or unknown formats.
- **Run-level Output:** An aggregated summary `report.json` must be emitted in the output directory.
- **Security Invariants:**
  - Strict input sanitization preventing path traversal (`Path(file).name`).
  - Allocation capping (max single read slice limited to 32 MB).
  - Memory bounds on record iteration (no runaway loops from fraudulent declared record counts).
- **Format Requirements:**
  - Initial validation gate: **LIBRA-98**
  - Block damage reporting: **LABLOG**
  - Archive/Index/RLE/XOR: **VAULT**
  - At least one game archive format (e.g. id Software PAK or WAD).
  - At least one legacy format (e.g. Lotus 1-2-3 `.WKS` or WordPerfect `.WPD`).

### Hypothesized:
- **Per-file Output Schema:** JSON files named `<filename>.json` corresponding to each recognized input file in `<output_dir>`.
- **Exit Code:** `0` on successful completion of a scan batch (even if individual input files contain damaged blocks or unknown formats). Non-zero exit code (`1`) is returned strictly on fatal invocation errors (e.g., non-existent input directory or bad CLI arguments).

### Unknown:
- **Authoritative JSON Schema:** The repository does not currently contain a `.json` schema file (e.g. `schema.json` or assignment schema document) specifying exact property keys required by an external auto-grader. The current JSON structure follows canonical recovery models (`file`, `format`, `file_size`, `records`, `damages`, `metadata`).

---

## 2. Format Analysis & Evidence Inventory

### 2.1 LIBRA-98 (Initial Gate)
- **Status:** **Unknown / Hypothesized Provisional Contract**
- **Authoritative Samples in Repository:** None currently present in workspace.
- **Known Requirements from Prompt:**
  - Acts as the initial validation gate.
  - Requires signature and version validation.
  - Header with record boundaries, counts, offsets, and field types.
  - Number, string, timestamp, date decoding.
  - Validation of record counts, offsets, lengths, field ranges, and checksums.
  - Recovery of complete records while reporting incomplete or corrupted trailing data.
- **Provisional Specification (Strictly for Defensive Testing):**
  - *Magic:* Exactly 8 bytes: `LIBRA98\x00` (`4C 49 42 52 41 39 38 00`).
  - *Endianness:* Little-endian (`<`).
  - *Header Fields (32 bytes):* Magic (8B), Version (2B uint16), Flags (2B uint16), Header Size (4B uint32), Record Count (4B uint32), Record Size (4B uint32), Header CRC32 (4B uint32), Reserved (4B).
  - *Record Layout (48 bytes):* Record ID (4B uint32), Timestamp (4B uint32), Status (2B uint16), Value (4B int32), Label (30B null-terminated), Record CRC16 (2B uint16), Reserved (2B).
  - *Audit Invariant:* Header size, record count, and record size are strictly checked against remaining buffer bounds to prevent integer overflows or unbounded iterations.
  - *Caution:* This layout is explicitly provisional. Do NOT claim compatibility with hidden external evaluator files until official binary samples or schema files are provided.

### 2.2 LABLOG (Block Checksums & Damage Reporting)
- **Status:** **Provisional Implementation (Evidence: Hypothesized)**
- **Authoritative Samples in Repository:** None currently present in workspace.
- **Provisional Specification Implemented:**
  - *Header (24 bytes):* Magic `LABLOG\x01\x00` (8B), Version (2B uint16), Block Count (2B uint16), Header CRC32 (4B uint32), Created Timestamp (8B uint64).
  - *Block Frame:* Sync marker `BLOK` (4B), Sequence ID (4B uint32), Block Type (2B uint16), Flags (2B uint16), Payload Length $N$ (4B uint32), Payload CRC32 (4B uint32), Timestamp (4B uint32), followed by $N$ bytes of payload.
  - *Recovery & Damage Isolation Mechanics:*
    - Independent per-block CRC32 verification. Checksum mismatch marks block as `corrupted` and logs `CHECKSUM_MISMATCH` damage without terminating iteration.
    - Subsequent valid blocks are successfully recovered even if preceding blocks are corrupted or truncated.
    - Resynchronization engine: scans for next `BLOK` sync marker when encountering malformed or desynchronized byte sequences.
    - Allocation safety: single block payload capped at 16 MB.
  - *Caution:* This layout is explicitly provisional. Passing synthetic tests validates the defensive parsing architecture, but does NOT prove compatibility with hidden external evaluator files.

### 2.3 VAULT (Index Table, RLE, XOR)
- **Status:** **Provisional Implementation (Evidence: Hypothesized)**
- **Authoritative Samples in Repository:** None currently present in workspace.
- **Provisional Specification Implemented:**
  - *Header (32 bytes):* Magic `VAULT\x01\x00\x00` (8B), Version (2B uint16), Flags (2B uint16), Entry Count (4B uint32), Index Offset (4B uint32), Index Length (4B uint32), Header CRC32 (4B uint32), Global XOR Key (4B uint32).
  - *Index Entry (48 bytes):* Entry ID (4B), Blob Offset (4B), Stored Size (4B), Decoded Size (4B), Flags (2B: bit 0 RLE, bit 1 XOR, bit 2 UTF8), XOR Key Byte (1B), Reserved (1B), Entry Name (24B null-terminated), Entry CRC32 (4B).
  - *Bounded RLE Decompressor:* PackBits / Byte-Run algorithm with strict output size cap (16 MB) to prevent zip-bomb attacks.
  - *XOR Deobfuscator:* Single-byte key or fallback to lowest byte of global archive key.
  - *Damage & Boundary Isolation:* Out-of-bounds offsets, decompression failures, or checksum mismatches in an entry do not terminate extraction of other valid archive entries.
  - *Caution:* This layout is explicitly provisional. Passing synthetic tests validates the defensive parsing architecture, but does NOT prove compatibility with hidden external evaluator files.

### 2.4 Game Archives & Real-World Legacy Formats

#### 2.4.1 Quake PAK (Game Archive)
- **Status:** **Documented Layout with Synthetic Tests (Evidence: Documented Specification)**
- **Authoritative Samples in Repository:** None present locally. Tested against documented id Software Quake PAK v1 specification.
- **Implementation Highlights:**
  - Strict 4-byte `PACK` magic check.
  - Directory offset and length bounds checked against file size; directory length must be multiple of 64 bytes.
  - Path traversal defense: `sanitize_path` removes drive prefixes (`C:`), leading slashes, and `..` components.
  - Range overlap validation (flagging directory-overlapping payloads or cross-entry overlaps).
  - Malformed payload offsets are reported as `MALFORMED_OFFSET` damage without aborting other entries.

#### 2.4.2 Lotus 1-2-3 .WKS (Legacy Spreadsheet)
- **Status:** **Documented Specification (Evidence: Verified against Primary & Well-Established Specifications)**
- **Authoritative Samples in Repository:** None present locally. Audited against Lotus 1-2-3 Release 1A specification (WSFF1.TXT / WSFF2.TXT), Gnumeric `lotus.c`, and LibreOffice Calc `sc/source/filter/lotus/`.
- **Opcode & Field Verification Log:**
  - `BOF` (`0x0000`): **Verified**. 2-byte version word (`0x0404` for 1-2-3 Release 1A `.WKS`, `0x0405` for Symphony / Release 2.x).
  - `EOF` (`0x0001`): **Verified**. 0-byte payload marking end of sequential stream.
  - `BLANK` (`0x000C`): **Verified**. 5-byte payload: Format byte (1B), Col uint16 (2B), Row uint16 (2B).
  - `INTEGER` (`0x000D`): **Verified**. 7-byte payload: Format byte (1B), Col uint16 (2B), Row uint16 (2B), Value signed int16 (2B).
  - `NUMBER` (`0x000E`): **Verified**. 13-byte payload: Format byte (1B), Col uint16 (2B), Row uint16 (2B), 8-byte IEEE 754 double precision float. Supported 15-byte payload fallback (10-byte 80-bit IEEE extended float).
  - `LABEL` (`0x000F`): **Verified**. Minimum 6 bytes: Format byte (1B), Col uint16 (2B), Row uint16 (2B), Align prefix byte (1B: `'`, `"`, `^`, `\`), followed by null-terminated ASCII / LMBCS string.
  - `FORMULA` (`0x0010`): **Verified**. Minimum 13 bytes: Format byte (1B), Col uint16 (2B), Row uint16 (2B), 8-byte float result, formula bytecode. Preserved as inert data without execution.
  - Cell address and format byte: **Verified**. Shared across all cell records: `+0x00` format byte (protection bit 7 + display format bits 0..6), `+0x01..+0x02` col (uint16 LE), `+0x03..+0x04` row (uint16 LE).
  - Record limits: **Verified defensive control**. Opcode payload length bounded by 64 KB; loop iteration bounded by 50,000 records.

---

## 3. Formats Evidence Inventory & Classification

| Format | Category | Specification Basis | Samples Tested | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| **LIBRA-98** | Provisional / Unverified | Inferred initial validation gate | Synthetic fixtures | Passing defensive unit tests |
| **LABLOG** | Provisional / Unverified | Inferred block-level journal | Synthetic fixtures | Passing block isolation tests |
| **VAULT** | Provisional / Unverified | Inferred archive + RLE + XOR | Synthetic fixtures | Passing bounded RLE & XOR tests |
| **PAK** | Documented layout | id Software Quake PAK specification | Synthetic & Hand-crafted independent fixtures | Passing path traversal & bounds tests |
| **WKS** | Documented layout (Verified) | Lotus 1-2-3 Release 1A specification (WSFF1.TXT) | Synthetic & Hand-crafted independent fixtures | Passing sequential cell record tests |
| **UNKNOWN** | Verified | General binary fallback | Random binary byte streams | Passing defensive catch-all tests |
| **EMPTY** | Verified | 0-byte file boundary | 0-byte file | Passing truncation tests |

---

## 4. Experiment & Audit Log

| Date | Hypothesis / Experiment | Result | Status |
| :--- | :--- | :--- | :--- |
| 2026-10-14 | Repository inspection for existing fixtures | Workspace is clean git repo, no files present | Confirmed empty |
| 2026-10-14 | Toolchain verification | Python 3.13.14 & Node v24.12.0 verified | Python 3.13 selected |
| 2026-10-14 | Initial implementation & 15 tests | Core infrastructure and provisional LIBRA-98 passing | Verified |
| 2026-10-14 | Focused Security Audit: Path Traversal | Filenames in `Reporter` now sanitized (`Path.name`) | Fixed & Tested |
| 2026-10-14 | Focused Security Audit: Weak Magic Heuristic | Removed loose short signature `LIB98\x00`; strictly enforced 8-byte `LIBRA98\x00` | Fixed & Tested |
| 2026-10-14 | Focused Security Audit: Adversarial Loop Counts | LIBRA-98 loop capped by actual byte bounds: `min(declared, (size - hdr)//rec_size)` | Fixed & Tested |
| 2026-10-14 | Security & Edge-Case Test Suite | Added 7 adversarial/security test cases (22 total tests) | All 22 Passing |
| 2026-10-14 | LABLOG provisional implementation | Block checksum isolation & sync marker resync | All 26 Passing |
| 2026-10-14 | VAULT provisional implementation | Bounded RLE PackBits & XOR deobfuscation | All 32 Passing |
| 2026-10-14 | PAK Quake archive & WKS Lotus 1-2-3 Release 1A | Path sanitization, cell decoding, sequential stream | All 43 Passing |
| 2026-10-14 | PS 02 Audit & Hardening: WKS Opcode Verification | Audited Lotus 1-2-3 opcodes 0x000C..0x0010 against WSFF1.TXT / Gnumeric / LibreOffice | Verified & Documented |
| 2026-10-14 | PS 02 Independent Fixtures & Circularity Break | Added hand-assembled spec byte fixtures (PAK, WKS, LIBRA, LABLOG, VAULT) labeled `[independent]` vs `[self-consistency]` | 52 Passing |
| 2026-10-14 | PS 02 Safety & Robustness Hardening | Added symlink escape prevention, output boundary containment, seed-deterministic fuzzing (50 iterations per parser), batch isolation, and RLE bomb protection | 64 Passing |
