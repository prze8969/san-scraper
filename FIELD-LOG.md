# FIELD-LOG: Reverse Engineering, Hypotheses, and Calibration Audit

This document maintains an evidence-driven log of binary format reverse-engineering, format discovery, structural hypotheses, and validation outcomes for **PS 02: Salvage** (Project: `san-scraper`).

---

## 1. High-Level Requirements & Execution Contract

### Verified Authoritative Requirements:
- **CLI Entrypoint:** `./salvage <input_dir> <output_dir>` exiting `0` without crashing on any input.
- **Offline Invariant:** Operates 100% offline using only Python 3.10+ standard library.
- **Per-file Output:** Writes `<output_dir>/<input_file_name>.json` containing `source_file`, `format`, `status`, `metadata`, `records`, and `damage`.
- **Run-level Output:** Writes `<output_dir>/report.json` with `tool_version`, `files`, and `totals`.
- **Authoritative Dataset:** Evaluated against `Genesis_Track3_PS2_Sample_Files-main/` containing 30 samples (`s01` through `s30`) and 7 golden reference files.

---

## 2. Reverse Engineering Milestones & Format Calibrations

### 2.1 LIBRA-98 (`s01.dat`, `s04.dat`)
- **Initial Hypothesis:** 8-byte magic `LIBRA98\x00` with 32-byte header and fixed 48-byte records.
- **Investigation & Finding:**
  - Examination of `s01.dat` revealed magic `LB98` (4 bytes).
  - Header is 16 bytes: `version(2B)`, `declared_count(2B)`, `dos_date(2B)`, `dos_time(2B)`, `data_offset(2B)`, `branch_id(2B)`.
  - Date decoding uses MS-DOS packed date format: `((date >> 9) & 0x7F) + 1980`.
  - Records begin with sync byte `0xA5`, length (1B), flags (1B), `id` (4B), Pascal string `title`, Pascal string `author`, `year_raw` (+1500), `price_cents` (2B), `copies` (1B), `isbn` (10B ASCII).
  - If flag bit 0 (`checked_out`) is set, a 2-byte DOS date follows as `due_date`.
- **Calibration Outcome:** **100% MATCH** with `s01.dat.json` and `s04.dat.json` (partial/truncated damage handling).

### 2.2 LABLOG (`s05.dat`, `s06.dat`, `s07.dat`)
- **Initial Hypothesis:** Magic `LABLOG\x01\x00` with `BLOK` sync markers.
- **Investigation & Finding:**
  - Header begins with `LLOG` (4 bytes), followed by `version(1B)`, `channels(1B)`, `interval_raw(2B)` (interval_ms = raw * 10), instrument string (16B), and 4-byte UTC timestamp.
  - Timestamp Epoch: Verified to be seconds since `1990-01-01 00:00:00 UTC` (`631152000` base Unix epoch).
  - Channel Calibration: Each channel specifies 4B unit, 4B float32 slope, 4B float32 intercept.
  - Data blocks begin with sync byte `0xB1`. Sample values are converted: `raw * slope + intercept`.
  - Sensor dropouts (`-32768` / `32767`) correctly emit `null`.
- **Calibration Outcome:** **100% MATCH** with `s05.dat.json`.

### 2.3 VAULT (`s08.dat`, `s09.dat`, `s10.dat`)
- **Initial Hypothesis:** Magic `VAULT\x01\x00\x00` with flat XOR key.
- **Investigation & Finding:**
  - Magic is `VLT1` (4 bytes) followed by `entry_count` (2B), `xor_key` (2B), flags (2B), and `index_offset` (4B).
  - Decryption Cipher: Names and text payloads use rolling XOR:
    $$\text{byte}_j \oplus ((\text{xor\_key} + j) \pmod{256})$$
  - Raw binary blobs (`.bin`) are stored unencrypted.
  - Blobs are prefixed with `b"BL"` + 2B record ID.
- **Calibration Outcome:** **100% MATCH** with `s08.dat.json`.

### 2.4 Lotus 1-2-3 WKS (`s11.wks`, `s12.wks`, `s13.wks`)
- **Investigation & Finding:**
  - BOF opcode `0x0000`, len 2, version `0x0404`.
  - Opcode `0x0008` (column width) has 3-byte payload: column (2B uint16) and width (1B uint8).
  - Opcode `0x0010` (formulas): stores cached float (8B), bytecode length at `payload[13:15]`, followed by raw formula bytecode.
  - Alignment characters: `'` (left), `"` (right), `^` (center), `\` (repeat).
- **Calibration Outcome:** **100% MATCH** with `s11.wks.json`.

### 2.5 Commodore 64 GEOS Convert CVT (`s17.cvt`, `s18.cvt`)
- **Investigation & Finding:**
  - Signature `PRG formatted GEOS file` and header code `0x83`.
  - Blocks are 254 bytes (C64 track/sector links stripped).
  - PETSCII translation table maps Commodore character codes to ASCII.
  - Info block in Block 1 parses filename, structure (`seq`/`vlir`), GEOS file type, modified timestamp, class, and author.
- **Calibration Outcome:** **100% MATCH** with `s18.cvt.json`.

### 2.6 IBM Mainframe EBCDIC Dump (`s19.000`, `s20.000`)
- **Investigation & Finding:**
  - 4-byte Record Descriptor Word (RDW) with big-endian length.
  - Encoding CP037.
  - Detail records decode student IDs, names, IBM COMP-3 packed decimal dates (`YYYY-MM-DD`), GPAs (`X.XX`), credits (uint16 BE), and signed balances.
  - Header and trailer records accurately populate metadata (`run_date`, `trailer_count`, `trailer_credits_total`).
- **Calibration Outcome:** **100% MATCH** with `s20.000.json`.

### 2.7 Other Real-World Formats Verified
- **WPD (WordPerfect):** Strips control codes and emits paragraph/page break records.
- **BRAVO (Xerox Alto):** Emits paragraphs delimited by CR (`\r`) before the `0x1A` trailer.
- **WAD (Doom):** Extracts lumps and computes SHA-256 hashes.
- **PAK (Quake):** Extracts directory entries and computes SHA-256 hashes.
- **UNKNOWN / EMPTY (`s26`):** Emits clean fallback with status `ok` format `UNKNOWN`.

---

## 3. Summary of Validation
- **Golden References:** 7 out of 7 matched (100%).
- **Full Sample Batch:** 30 out of 30 processed with exit code 0.
- **Automated Test Discovery:** 55 out of 55 tests passing in `tests/`.
