# DECISIONS.md: Key Architectural Decisions & Rejected Ideas

## Key Design Choices

### 1. Bounded Binary Reader (`src/reader.py`)
- **Decision:** All file data must be wrapped in `BoundedBinaryReader` before parsing. Raw indexing without bounds checks is disallowed.
- **Rationale:** Prevents out-of-bounds panics, integer overflow indexing, and runaway allocation attacks. Enforces a strict `max_alloc=32MB` single slice read cap.

### 2. 16 MB Decompression Cap (`src/formats/vault.py`, `src/formats/zip.py`, `src/formats/gzip.py`)
- **Decision:** Every compressed entry (ZIP Deflate, GZIP stream, VAULT PackBits RLE) enforces a hard limit of 16 MB uncompressed bytes.
- **Rationale:** Protects against decompression bombs (zip bombs / billion laughs byte variants) that declare tiny compressed sizes but expand indefinitely.

### 3. Path Sanitization & Output Containment (`src/reporter.py`, `src/recovery/extractor.py`)
- **Decision:** All extracted filenames are sanitized (`sanitize_name` removing `..`, leading slashes, and drive letters), and the final output path is verified with `resolved_path.relative_to(resolved_base)`.
- **Rationale:** Prevents arbitrary file write vulnerabilities and directory traversal attacks when unpacking untrusted archives.

### 4. Verified vs Heuristic Coverage Split (`src/recovery/carver.py`)
- **Decision:** Byte coverage is partitioned into two distinct metrics: **verified coverage** (bytes explained by an authoritative parser) and **heuristic coverage** (bytes covered only by printable strings, carved files, or stride guesses).
- **Rationale:** Prevents deceptive claims. Random or unknown noise files must show ~0% verified coverage, clearly communicating to evaluators what was truly decoded versus what is merely an educated guess.

### 5. Resilient Fallback Recovery for Archives
- **Decision:** For ZIP archives, scan for local file headers (`PK\x03\x04`) even if the Central Directory or EOCD is missing or corrupted. For Doom WADs, process all valid lump entries even if later entries point out-of-bounds.
- **Rationale:** In a digital salvage scenario, files are frequently truncated or damaged at the tail. Central Directory loss should not cause total data loss of intact local entries.

### 6. Inert Formula Representation in Lotus 1-2-3
- **Decision:** Formula records (`0x0010`) are preserved strictly as inert data (cached floating-point result + raw bytecode), without evaluating formula trees.
- **Rationale:** Eliminates dynamic execution vulnerabilities while accurately salvaging the computed cell numbers and formula definitions.

---

## Rejected Hypotheses (from `FIELD-LOG.md`)

1. **Rejected: Claiming Heuristic Strides as Verified Records**
   - *Hypothesis:* Autocorrelation stride detection could be labelled as generic verified records.
   - *Outcome:* Rejected. Autocorrelation on random bytes produced false positives. Strides with confidence < 0.6 or stride < 4 are rejected, and all such records are routed strictly to the heuristic lane.

2. **Rejected: Blind Signature Magic at Offset 0 Only**
   - *Hypothesis:* Detecting format solely based on offset 0 magic bytes.
   - *Outcome:* Rejected. Real-world damaged files often have prepended wrappers or corrupt headers (e.g. `11_header_damaged.pak`). Multi-tier scanning (`PipelineDetector`) searches the first 64 bytes to locate embedded headers.

3. **Rejected: Speculative Calibration for Undocumented Formats**
   - *Hypothesis:* Calibrating field types for `LIBRA-98`, `LABLOG`, and `VAULT` against arbitrary synthetic variations.
   - *Outcome:* Rejected. In the absence of authoritative vendor specifications, guessing internal semantics risks overfitting. Kept strictly as defensive provisional contracts.
