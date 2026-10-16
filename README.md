# PS 02 — SALVAGE: Legacy Binary Recovery Engine (`salvage`)

A defensive, high-reliability binary recovery engine built for recovering structured records from legacy, corrupted, truncated, and sync-framed binary files.

Built strictly using the **Python 3.11+ Standard Library** (`struct`, `json`, `hashlib`, `datetime`, `math`, `zlib`, `binascii`, `pathlib`, `unittest`). Runs 100% offline with zero third-party packages.

---

## 1. Architecture & Design Principles

The engine is engineered around a 6-stage recovery pipeline:

```text
[ Raw File ]
     │
     ▼
[ Stage 1: FormatRouter ] ──────── Magic bytes, heuristics & extension detection
     │
     ▼
[ Stage 2: SafeByteCursor ] ────── Bounds-checked I/O, byte claim tracking & sync carving
     │
     ▼
[ Stage 3: Transforms ] ────────── CRC16/32, Fletcher, PackBits RLE, rolling XOR & DOS dates
     │
     ▼
[ Stage 4: FormatDecoders ] ────── Domain-specific decoders (LIBRA-98, LABLOG, VAULT, WKS, ...)
     │
     ▼
[ Stage 5 & 6: JsonEmitter ] ───── Schema-compliant per-file JSON & aggregated report.json
```

### Safety & Resilience Invariants:
- **Zero-Crash Guarantee:** The CLI entrypoint `./salvage` never crashes, hangs, or exits with a non-zero exit code regardless of corrupt bytes, zip-bomb decompression loops, out-of-bounds pointers, or 0-byte files.
- **Bounds Checking & Memory Caps:** All reads are strictly bounded by file length. RLE decompression routines enforce a 16 MB cap to mitigate zip-bomb payloads.
- **Sync Word Carving:** Stream formats (`0xA5` for `LIBRA-98`, `0xB1` for `LABLOG`, cell opcodes for `WKS`) resynchronize after corrupt bytes and report skipped spans in the damage report.
- **Containment & Immutability:** Input files are strictly opened in binary read mode (`rb`). Output files are verified against directory traversal and symlink escape attacks.

---

## 2. Supported Formats (10 Legacy Formats)

1. **LIBRA-98:** Municipal library circulation database (`LB98`), packed MS-DOS dates, `0xA5` sync framing, decoy length fields.
2. **LABLOG:** Laboratory instrument telemetry logs (`LLOG`), calibrated sensor channels, `0xB1` / `0xAA55` sync carving, dropout nulls.
3. **VAULT:** Encrypted container archive (`VLT1`), rolling XOR ciphers, PackBits RLE decompression, SHA-256 integrity verification.
4. **Lotus 1-2-3 (.WKS):** Real-world spreadsheet TLV streams (`BOF` 0x0000, labels, integers, numbers, formula bytecodes).
5. **WordPerfect (.WPD):** Corel WordPerfect documents (`\xFFWPC`), control code filtering, paragraph and page break extraction.
6. **Xerox Alto Bravo (.BRAVO):** 1970s research lab editor documents, CR-delimited text paragraphs, formatting trailer runs.
7. **Commodore 64 GEOS (.CVT):** GEOS convert container, PETSCII translation, sequential and VLIR scrap record extraction.
8. **IBM Mainframe Tape (.000):** EBCDIC CP037 student records, supporting both unblocked (RDW) and Variable Blocked (BDW+RDW) mainframe formats with COMP-3 packed decimals.
9. **Doom WAD (.WAD):** PWAD/IWAD game data archives with directory lump extraction and SHA-256 hashes.
10. **Quake PAK (.PAK):** PACK game archives with 64-byte directory entries and SHA-256 hashes.

---

## 3. Quick Start & Execution Guide

### One-Command Build & Verification:

```bash
# Compile and verify syntax of all python modules
make build

# Run comprehensive 60-test test suite
make test

# Generate clean & corrupted test vectors
make samples

# Run salvage on generated test vectors
make run
```

### Running on Participant Kit Samples:

```bash
# Linux / macOS:
./salvage Genesis_Track3_PS2_Sample_Files-main/samples final_output

# Windows PowerShell:
python -m src.cli Genesis_Track3_PS2_Sample_Files-main/samples final_output
# or via batch wrapper:
.\salvage.bat Genesis_Track3_PS2_Sample_Files-main/samples final_output
```

---

## 4. Offline Docker Build & Run

The repository includes a completely offline `Dockerfile` built on `python:3.11-slim` with zero network access during build or run:

```bash
# Build the container locally
docker build -t salvage .

# Run salvage offline mounting input and output folders
docker run --rm \
  -v $(pwd)/Genesis_Track3_PS2_Sample_Files-main/samples:/data/in:ro \
  -v $(pwd)/final_output:/data/out \
  salvage /data/in /data/out
```

---

## 5. Output Schema

The engine writes `<output_dir>/<input_file_name>.json` for each file and an aggregated `report.json`:

```json
{
  "source_file": "s01.dat",
  "format": "LIBRA-98",
  "status": "ok",
  "metadata": {
    "version": 2,
    "created": "1998-10-03T11:20:22",
    "branch_id": 576,
    "declared_record_count": 5
  },
  "records": [
    {
      "id": 1002,
      "title": "Dracula",
      "author": "Bram Stoker",
      "year": 1897,
      "price_cents": 499,
      "copies": 3,
      "isbn": "4010278714",
      "checked_out": false,
      "due_date": null
    }
  ],
  "damage": []
}
```

---

## 6. Verification Status

- **Golden Reference Calibration:** 7/7 (100% exact match against `expected_outputs/`).
- **Participant Kit Ingestion:** 30/30 files processed cleanly with exit code 0.
- **Unit & Security Test Suite:** 60/60 tests passing in `tests/`.
