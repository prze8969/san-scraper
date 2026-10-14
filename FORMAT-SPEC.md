# FORMAT-SPEC: Binary Format Specifications & Defensive Parsing Rules

This document specifies the binary format structures, decoding rules, and boundaries recognized by `san-scraper` (`salvage`).

> [!WARNING]
> Formats marked as **PROVISIONAL** are designed for defensive parsing engine verification only and represent provisional hypotheses where official authoritative specification files have not yet been provided.

---

## 1. General Defensive Parsing Constraints

All parsers within `san-scraper` must enforce the following invariants:
1. **Memory Bound:** Never allocate buffer sizes derived directly from an untrusted file header without validating against total remaining file size. Maximum single allocation cap: **32 MB**.
2. **Offset & Slice Bounds:** All reads must pass through `BoundedBinaryReader`. An out-of-range read produces a catchable `TruncationError` or `BoundsError`, never an unhandled exception.
3. **Loop Bounds:** Record count loops are strictly bounded by `min(header_declared_count, remaining_bytes // min_record_size)`.
4. **String Decoding:** String fields must use safe decoding with replacement (`errors="replace"`), null-terminator trimming, and maximum length truncation.
5. **Checksum Verification:** Checksum errors must be flagged in the damage report without immediately aborting parsing of subsequent or salvageable records.

---

## 2. Format Specifications

### 2.1 LIBRA-98 [PROVISIONAL]

- **Evidence Level:** Hypothesized / Provisional Contract (No authoritative reference file provided).
- **Endianness:** Little-endian (`<`).
- **Signature:** 8 bytes: `LIBRA98\x00` (`4C 49 42 52 41 39 38 00`).
- **Header Layout:**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Magic | 8 bytes | `LIBRA98\x00` |
  | 0x08 | Version | uint16 | Expected `0x0100` (1.0) or `0x0101` |
  | 0x0A | Flags | uint16 | Bitflags (bit 0: checksum enabled) |
  | 0x0C | Header Size | uint32 | Size of header in bytes (typically 32) |
  | 0x10 | Record Count | uint32 | Number of declared records |
  | 0x14 | Record Size | uint32 | Declared record size (0 for variable) |
  | 0x18 | Checksum | uint32 | CRC32 of header bytes 0x00..0x17 |
  | 0x1C | Reserved | 4 bytes | Zero padding |

- **Record Layout (Fixed 48-byte variant):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | +0x00 | Record ID | uint32 | Unique sequential record ID |
  | +0x04 | Timestamp | uint32 | Unix timestamp (seconds since epoch) |
  | +0x08 | Status / Flags | uint16 | Record status bitmask |
  | +0x0A | Value | float32 or int32 | Recorded numeric value |
  | +0x0E | Label / Name | 30 bytes | ASCII / UTF-8 null-terminated string |
  | +0x2C | Record CRC16 | uint16 | CRC-16 of preceding record bytes |

- **Damage Scenarios:**
  - *Header CRC mismatch:* Flagged as damaged header, attempt record salvage if record boundary magic aligns.
  - *Truncated file:* Parse all intact records; trailing partial bytes emitted as `damaged_tail`.
  - *Record CRC mismatch:* Individual record marked as `status: "corrupted"`, data extracted as best-effort.

---

### 2.2 LABLOG [PROVISIONAL SPECIFICATION]

- **Evidence Level:** Hypothesized / Provisional Contract (No authoritative reference sample provided in workspace).
- **Endianness:** Little-endian (`<`).
- **Signature:** 8 bytes: `LABLOG\x01\x00` (`4C 41 42 4C 4F 47 01 00`).
- **Header Layout (24 bytes):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Magic | 8 bytes | `LABLOG\x01\x00` |
  | 0x08 | Version | uint16 | Expected `0x0001` |
  | 0x0A | Block Count | uint16 | Declared total number of blocks in file |
  | 0x0C | Header Checksum | uint32 | CRC32 of bytes 0x00..0x0B |
  | 0x10 | Created Timestamp | uint64 | Unix timestamp (seconds or milliseconds) |

- **Block Frame Layout (Self-contained Block, minimum 24 bytes header + variable payload):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | +0x00 | Block Sync Magic | 4 bytes | `BLOK` (`42 4C 4F 4B`) |
  | +0x04 | Block Sequence ID | uint32 | Monotonically increasing block index (0, 1, 2, ...) |
  | +0x08 | Block Type / Level | uint16 | Log severity / block type (e.g. 1=INFO, 2=WARN, 3=DATA) |
  | +0x0A | Flags | uint16 | Block flags (bit 0: compressed, bit 1: checksum_verified) |
  | +0x0C | Payload Length | uint32 | Declared payload length $N$ in bytes |
  | +0x10 | Payload CRC32 | uint32 | CRC32 over the payload bytes (+0x18..+0x18+N) |
  | +0x14 | Block Timestamp | uint32 | Unix timestamp of block generation |
  | +0x18 | Payload Data | $N$ bytes | Text/data bytes (UTF-8/ASCII) |

- **Block Isolation & Recovery Mechanics:**
  1. **Independent Validation:** Each block computes CRC32 strictly over its payload slice. If the checksum fails, that block is marked `status: "corrupted"`, recorded in `damages` as `CHECKSUM_MISMATCH`, but does NOT stop iteration.
  2. **Boundary Truncation:** If file ends before `+0x18 + N`, the block is flagged `TRUNCATION` and partially recovered if partial bytes exist.
  3. **Resynchronization Scan:** If a block header is malformed (missing `BLOK` sync magic), the parser scans forward byte-by-byte (up to remaining file limit) for the next `BLOK` sequence magic, logging the skipped byte span as an unrecoverable damage block.
  4. **Allocation Limit:** Declared payload length $N$ is capped at `min(declared_length, remaining_bytes)`. If declared length exceeds `16 MB`, the block is flagged as `INVALID_HEADER` and rejected.

---

### 2.3 VAULT [PROVISIONAL SPECIFICATION]

- **Evidence Level:** Hypothesized / Provisional Contract (No authoritative reference sample provided in workspace).
- **Endianness:** Little-endian (`<`).
- **Signature:** 8 bytes: `VAULT\x01\x00\x00` (`56 41 55 4C 54 01 00 00`).
- **Header Layout (32 bytes):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Magic | 8 bytes | `VAULT\x01\x00\x00` |
  | 0x08 | Version | uint16 | Expected `0x0001` |
  | 0x0A | Flags | uint16 | Archive flags |
  | 0x0C | Entry Count | uint32 | Declared number of files/entries in the index |
  | 0x10 | Index Offset | uint32 | Offset to start of the index table |
  | 0x14 | Index Length | uint32 | Total byte size of the index table |
  | 0x18 | Header Checksum | uint32 | CRC32 over header bytes 0x00..0x17 |
  | 0x1C | Global XOR Key | uint32 | Archive-wide 4-byte XOR mask |

- **Index Entry Layout (48 bytes per entry):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | +0x00 | Entry ID | uint32 | Unique entry identifier |
  | +0x04 | Blob Offset | uint32 | Absolute offset to the blob in file |
  | +0x08 | Stored Size | uint32 | Size of the blob as stored (compressed/obfuscated) |
  | +0x0C | Decoded Size | uint32 | Expected size after decompression/unmasking |
  | +0x10 | Entry Flags | uint16 | Bit 0: RLE compressed; Bit 1: XOR obfuscated; Bit 2: UTF-8 string |
  | +0x12 | XOR Key Byte | uint8 | Single-byte XOR key (or fallback to global key) |
  | +0x13 | Reserved | 1 byte | Zero padding |
  | +0x14 | Entry Name | 24 bytes | Null-terminated entry label/name |
  | +0x2C | Entry CRC32 | uint32 | Expected CRC32 of decoded payload |

- **Bounded RLE Compression Specification:**
  - PackBits / Byte-Run variant:
    - Control byte $B$:
      - If $0 \le B \le 127$: Literal run of $B + 1$ bytes follows.
      - If $-128 \le B \le -1$ (signed) or $129 \le B \le 255$ (unsigned): Repeat the next single byte $257 - B$ times (i.e. $2$ to $128$ repetitions).
      - If $B = 128$ (`0x80`): No-op / padding byte.
  - **Decompression Limit:** Maximum decoded output buffer is strictly bounded by `min(declared_decoded_size, 32 MB)`. Any stream attempting to produce more output is halted with `DECOMPRESSION_ERROR`.

- **XOR Obfuscation Specification:**
  - If Bit 1 of Entry Flags is set:
    - Byte-wise XOR applied to payload using `XOR Key Byte` (or lowest byte of `Global XOR Key` if `XOR Key Byte == 0`).
    - Decoding order: XOR unmasking is applied before RLE decompression if compressed, or directly on literal string if uncompressed.

- **Defensive Index and Blob Validation:**
  1. `Index Offset` and `Index Length` are verified against `file_size`.
  2. For each entry, `Blob Offset` and `Stored Size` must satisfy `offset + size <= file_size`. Overlapping or out-of-file entries are rejected and logged as `MALFORMED_OFFSET`.
  3. Corruption in one entry blob does NOT terminate extraction of subsequent entries.

---

### 2.4 Quake PAK (Game Archive) [DOCUMENTED SPECIFICATION]

- **Evidence Level:** Documented Layout with Synthetic Tests (id Software Quake binary archive specification).
- **Endianness:** Little-endian (`<`).
- **Signature:** 4 bytes: `PACK` (`50 41 43 4B`).
- **Header (12 bytes):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Magic | 4 bytes | `PACK` |
  | 0x04 | Directory Offset | uint32 | Byte offset to directory table |
  | 0x08 | Directory Length | uint32 | Total byte size of directory table (must be divisible by 64) |
- **Directory Entry (64 bytes each):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Filename | 56 bytes | Null-terminated string (ASCII / Latin-1) |
  | 0x38 | File Offset | uint32 | Absolute offset to file payload in PAK |
  | 0x3C | File Size | uint32 | Declared size of file payload |
- **Security & Defensive Controls:**
  - `sanitize_path`: Untrusted filenames are stripped of drive letters, leading slashes, and `..` traversal segments.
  - Payloads are checked against `file_size` boundaries. Corrupt entry offsets are reported as `MALFORMED_OFFSET` while preserving intact entries.
  - Overlapping ranges (with directory or other payloads) are flagged as warnings in the record.

---

### 2.5 Lotus 1-2-3 .WKS (Legacy Spreadsheet) [DOCUMENTED SPECIFICATION]

- **Evidence Level:** Documented Layout with Independent & Synthetic Tests.
- **Authoritative References:**
  1. *Lotus 1-2-3 File Format Specification* (Lotus Development Corporation, WSFF1.TXT / WSFF2.TXT).
  2. *Gnumeric spreadsheet filter source*: `plugins/lotus-123/lotus.c` (GNOME GitLab).
  3. *LibreOffice Calc import filter*: `sc/source/filter/lotus/lotimpop.cxx` (Document Foundation).
- **Endianness:** Little-endian (`<`).
- **Structural Model:** Sequential record stream:
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | Opcode | uint16 | Record type identifier |
  | 0x02 | Length $N$ | uint16 | Length of data payload |
  | 0x04 | Payload | $N$ bytes | Record-specific payload |
- **Cell Address and Format Byte Layout (Shared by all cell records):**
  - Offset `+0x00`: Format byte (1 byte)
    - Bit 7: Protection flag (1 = protected, 0 = unprotected)
    - Bits 0..6: Display format (0 = Fixed, 1 = Scientific, 2 = Currency, 3 = Percent, etc.)
  - Offset `+0x01..+0x02`: Column index (uint16, 0-indexed, 0..255 for Release 1A)
  - Offset `+0x03..+0x04`: Row index (uint16, 0-indexed, 0..2047 for Release 1A)
- **Canonical Record Opcodes & Body Layouts:**
  - `0x0000` (**BOF** - Verified): Beginning of file. Payload = 2-byte version word (`0x0404` for Lotus 1-2-3 Release 1A `.WKS`; `0x0405` for Symphony / Release 2.x).
  - `0x0001` (**EOF** - Verified): End of file. Payload = 0 bytes.
  - `0x000C` (**BLANK** - Verified): Empty formatted cell. Payload = 5 bytes: Format byte (1B), Col (2B uint16), Row (2B uint16).
  - `0x000D` (**INTEGER** - Verified): Short integer cell. Payload = 7 bytes: Format byte (1B), Col (2B uint16), Row (2B uint16), Value (2B signed int16).
  - `0x000E` (**NUMBER** - Verified): Double-precision numeric cell. Payload = 13 bytes (standard IEEE 754 64-bit double: 1B format, 2B col, 2B row, 8B double) or 15 bytes (10-byte 80-bit IEEE extended float fallback).
  - `0x000F` (**LABEL** - Verified): Text string cell. Payload $\ge$ 6 bytes: Format byte (1B), Col (2B uint16), Row (2B uint16), Alignment prefix byte (1B: `'` Left, `"` Right, `^` Center, `\` Repeat), null-terminated ASCII/LMBCS text string ($N-6$ bytes).
  - `0x0010` (**FORMULA** - Verified): Calculated formula cell. Payload $\ge$ 13 bytes: Format byte (1B), Col (2B uint16), Row (2B uint16), cached float result (8B double), formula expression bytecode. Treated strictly as inert non-executable data.
- **Defensive & Compatibility Handling:**
  - Alternate compatibility mapping: If `0x000C` has 7 bytes, parsed as INTEGER; `0x000D` with 13 bytes as NUMBER; `0x000E` with $\ge 6$ bytes as LABEL.
  - Other/unknown opcodes: Preserved safely as `UNKNOWN_OPCODE_0x...` with raw hex representation without halting parser. Missing `EOF` (`0x0001`) logged as `TRUNCATION` damage. Max record size clamped to 64 KB and loop bounded to 50,000 records.
