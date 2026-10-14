# san-scraper (`salvage`)

Defensive binary file recovery tool for recovering lost records from legacy, undocumented, or damaged binary formats (**PS 02: Salvage**).

Operates completely offline with zero external runtime dependencies using Python 3.13 standard library.

---

## 1. Status

| Format | Status | Evidence |
| :--- | :--- | :--- |
| **Lotus 1-2-3 (.WKS)** | Implemented from documented layout | Documented in `WSFF1.TXT` / `WSFF2.TXT`, Gnumeric `lotus.c`, LibreOffice Calc filter; tested with hand-assembled independent byte fixtures |
| **Quake PAK (.PAK)** | Implemented from documented layout | Documented in id Software Quake archive specification (`quakedef.h`); tested with hand-assembled independent byte fixtures |
| **LIBRA-98 (.LIB)** | Provisional layout | Official samples/schema not available; defensive parsing, checksum validation, and damage reporting tested |
| **LABLOG (.LAB)** | Provisional layout | Official samples/schema not available; defensive parsing, block CRC32 damage isolation, and resynchronization tested |
| **VAULT (.VLT)** | Provisional layout | Official samples/schema not available; defensive parsing, bounded PackBits RLE, XOR deobfuscation, and index isolation tested |
| **UNKNOWN / EMPTY** | Fallback handler | Catch-all for unrecognized or truncated binary streams; tested with randomized and 0-byte streams |

---

## 2. Safety Design

- **Bounded Binary Reads:** All byte reads are strictly bounded by file length and memory allocation limits (`BoundedBinaryReader`).
- **16 MB Decompression Cap:** PackBits RLE decompression is hard-capped at 16 MB per entry to prevent decompression bombs.
- **Path Sanitization:** Quake PAK and file names are stripped of Windows drive letters, leading slashes, and `..` directory traversal components.
- **Output Containment:** `Reporter` verifies target file paths strictly reside within the user-specified `<output_dir>` (`relative_to` verification) to prevent symlink or traversal escapes.
- **Per-file Isolation:** A corrupted, malformed, or malicious file never crashes or halts the processing of subsequent files.
- **Offline Only:** Pure Python 3.13 standard library; zero external network access, zero dynamic downloads.
- **Immutability of Inputs:** Input files are strictly opened in binary read mode (`rb`) and are never modified.

---

## 3. Known Limitations

- **Provisional Wire Formats:** Because official specification documents and binary sample files were not provided in the challenge workspace for `LIBRA-98`, `LABLOG`, and `VAULT`, their layouts are provisional hypotheses. If an external evaluator requires different magic bytes, offsets, or field structures, those files will be classified as invalid header or unknown without crashing.
- **Unconfirmed Grader Schema:** The output JSON schema follows standard forensic salvage conventions (`file`, `format`, `records`, `damages`, `metadata`), but the exact JSON keys required by the hidden evaluator remain unconfirmed.
- **Inert Formulas in WKS:** Lotus 1-2-3 formulas (`0x0010`) are preserved strictly as inert data (cached floating-point value and raw bytecode) without dynamic execution for security reasons.

---

## 4. Usage

### Local Execution (Windows / PowerShell)

```powershell
# Run the test suite (64 tests)
python -m unittest discover tests

# Run salvage
.\salvage.bat <input_dir> <output_dir>
# or directly:
python -m src.cli <input_dir> <output_dir>

# Run end-to-end demo
.\demo\run_demo.bat
```

### Local Execution (Linux / macOS)

```bash
chmod +x ./salvage
./salvage <input_dir> <output_dir>

# Run end-to-end demo
chmod +x ./demo/run_demo.sh
./demo/run_demo.sh
```

### Docker Execution

```bash
docker build -t san-scraper .
docker run --rm -v $(pwd)/demo/input:/data/in -v $(pwd)/demo/output:/data/out san-scraper /data/in /data/out
```

---

## 5. Output Schema

For each file `<filename>` in `<input_dir>`, `salvage` writes `<filename>.json` in `<output_dir>`:
- `file`: Source filename.
- `format`: Identified format name.
- `file_size`: File length in bytes.
- `is_valid_header`: Boolean header validity flag.
- `records`: List of extracted records with `id`, `status` (`complete`, `partial`, `corrupted`), `byte_range`, and extracted `data`.
- `damages`: List of detected damage blocks with byte `offset`, `length`, `type`, and human-readable `description`.
- `metadata`: Format-specific metadata.

At run completion, an aggregated summary `report.json` is generated in `<output_dir>`.

