# FORMAT-SPEC: Authoritative Binary Format Specifications & Defensive Parsing Rules

This document specifies the exact byte structures, field types, decoding algorithms, endianness, checksum polynomials, and defensive recovery state machines verified and calibrated against the official Problem Statement 02 Participant Kit (`Genesis_Track3_PS2_Sample_Files-main/`).

---

## 1. Defensive Parsing & Architectural Invariants

All format recovery modules in `salvage` adhere strictly to these invariants:
1. **Zero-Crash Guarantee (Exit Code 0):** Unhandled exceptions are caught at the engine boundary and mapped to `status: "failed"` or `"unrecognized"`. The CLI runner always exits with code `0`.
2. **Defensive Memory & Allocation Bounds:** Buffer allocations are strictly bounded by `min(declared_size, remaining_file_bytes)`. Decompression routines cap output at 16 MB (`rle_decompress_packbits`).
3. **Resynchronization & Sync Word Carving:** In continuous streams (`LIBRA-98`, `LABLOG`, `WKS`), damaged byte spans are recorded as `unparsed_bytes` while scanning forward to the next valid record sync boundary (`0xA5` for LIBRA, `0xB1` / `0xAA55` for LABLOG).
4. **Offline & Zero Dependencies:** Operates using 100% standard Python 3.11+ library modules (`struct`, `json`, `hashlib`, `datetime`, `math`, `binascii`).
5. **Strict Schema Compliance:** All outputs conform strictly to `OUTPUT-CONTRACT.md`.

---

## 2. Format Specifications (10 Formats)

### 2.1 LIBRA-98 (Municipal Library Circulation Database)
* **Magic:** `LB98` (`4C 42 39 38`) at offset `0x00`.
* **Header Layout (16 bytes, Little-Endian):**
  ```text
  +-------------------+-------------------+-------------------+-------------------+
  | magic "LB98" (4B) | version (u16)     | declared_count(u16| dos_date (u16)    |
  +-------------------+-------------------+-------------------+-------------------+
  | dos_time (u16)    | data_offset (u16) | branch_id (u16)   |                   |
  +-------------------+-------------------+-------------------+-------------------+
  ```
  - `dos_date`: Packed MS-DOS format: $\text{Year} = ((val \gg 9) \ \& \ 0\text{x}7\text{F}) + 1980$, $\text{Month} = (val \gg 5) \ \& \ 0\text{xF}$, $\text{Day} = val \ \& \ 0\text{x}1\text{F}$.
  - `dos_time`: Packed MS-DOS format: $\text{Hour} = (val \gg 11) \ \& \ 0\text{x}1\text{F}$, $\text{Minute} = (val \gg 5) \ \& \ 0\text{x}3\text{F}$, $\text{Second} = (val \ \& \ 0\text{x}1\text{F}) \times 2$.
* **Record Structure (Sync-Framed with `0xA5`):**
  - `0x00`: Sync byte `0xA5`.
  - `0x01`: `rec_len` (uint8) — Payload length following this byte.
  - `0x02`: `flags` (uint8) — Bit 0 (`0x01`): `checked_out`, Bit 1 (`0x02`): `deleted`, Bit 2 (`0x04`): `reference_only`.
  - `+0x00`: `id` (uint32 LE).
  - `+0x04`: `title_len` (uint8) + `title` (CP437 string).
  - `+idx`: `author_len` (uint8) + `author` (CP437 string).
  - `+idx`: `year_raw` (uint16 LE) — $\text{year} = \text{year\_raw} + 1500$.
  - `+idx`: `price_cents` (uint16 LE).
  - `+idx`: `copies` (uint8).
  - `+idx`: `isbn` (10 bytes ASCII).
  - If `checked_out`: `due_date` (uint16 LE MS-DOS Date formatted as `YYYY-MM-DD`, else `null`).
* **Trailer:** `END!` marker terminates the circulation record stream.

---

### 2.2 LABLOG (Laboratory Journal & Instrument Telemetry Stream)
* **Magic:** `LLOG` (`4C 4C 4F 47`) at offset `0x00`.
* **File Header Layout (32 bytes, Little-Endian):**
  - `0x00..0x03`: Magic `LLOG` (`4C 4C 4F 47`).
  - `0x04`: `version` (uint8) = 1.
  - `0x05`: `num_channels` (uint8).
  - `0x06..0x07`: `interval_raw` (uint16 LE) — $\text{sample\_interval\_ms} = \text{raw} \times 10$.
  - `0x08..0x17`: `instrument` (16 bytes null-padded ASCII).
  - `0x18..0x1B`: `start_ts` (uint32 LE) — Epoch seconds since `1990-01-01 00:00:00 UTC` (Unix timestamp `631152000`).
  - `0x1C..0x1D`: `declared_block_count` (uint16 LE).
  - `0x1E..0x1F`: `hdr_crc` (uint16 LE) — Computed over bytes `0x00..0x1D` (first 30 bytes) using **CRC-16/CCITT-FALSE** ($\text{poly}=0\text{x}1021, \text{init}=0\text{xFFFF}, \text{xorout}=0\text{x}0000$).
* **Block Framing & Checksum Specification:**
  Every block in the file (starting at offset `0x20` with the Channels Block) adheres to the exact framing:
  ```text
  +-------------+-------------+------------------+-----------------------+---------------------+
  | sync (0xB1) | type (uint8)| len (uint16 LE)  | payload (len bytes)   | stored_crc(u16 LE)  |
  +-------------+-------------+------------------+-----------------------+---------------------+
  ```
  - **Exact Checksum Formula:** **CRC-16/CCITT-FALSE** ($\text{poly}=0\text{x}1021, \text{init}=0\text{xFFFF}, \text{xorout}=0\text{x}0000, \text{refin}=\text{False}, \text{refout}=\text{False}$).
  - **Checksum Calculation Span:** Evaluated over `type (1 byte) + len (2 bytes) + payload (len bytes)`. The leading `0xB1` sync byte is excluded from the CRC calculation.
* **Block Types:**
  - **Type 0x03 (CHANNELS Descriptor Block):**
    - Directly follows header at offset `0x20` (`32`).
    - Payload contains `num_channels * 12` bytes:
      - `+0x00..0x03`: Unit (4 bytes ASCII null-padded, e.g. `mV\x00\x00`, `pH\x00\x00`, `kPa\x00`, `degC`).
      - `+0x04..0x07`: `slope` (IEEE 754 32-bit float LE).
      - `+0x08..0x0B`: `intercept` (IEEE 754 32-bit float LE).
    - Trailed by 2-byte CRC16 LE.
  - **Type 0x01 (SAMPLES Telemetry Data Block):**
    - `+0x00..0x01`: `start_sample` (uint16 LE) — Global sample index.
    - `+0x02`: `sample_count` (uint8) — Number of consecutive time slices.
    - `+0x03..end`: `sample_count * num_channels * 2` bytes of 16-bit signed integers (int16 LE).
    - Physical calibration: $\text{val} = \text{round}(\text{raw} \times \text{slope} + \text{intercept}, 4)$.
    - Sensor dropouts: Raw values `-32768` (`0x8000`) or `32767` (`0x7FFF`) represent sensor failure / rail dropout and are converted to `null`.
    - Trailed by 2-byte CRC16 LE.
  - **Type 0x02 (EVENT Marker Block):**
    - `+0x00..0x01`: `sample` (uint16 LE) — Sample index where event occurred.
    - `+0x02`: `severity` (uint8) — Event severity level (0 = info, 1 = warning, 2 = critical).
    - `+0x03`: `msg_len` (uint8) — Length of event annotation.
    - `+0x04..end`: ASCII message text.
    - Trailed by 2-byte CRC16 LE.
* **Corruptions & Recovery Rules:**
  - If any block CRC fails to match `stored_crc`, record damage `kind: "crc_mismatch"` at CRC offset, mark file `status: "partial"`, and proceed to recover records safely.
  - In `s07.dat`, Block 04 at offset 169 (`len=39`) has corrupted telemetry bytes (`stored=0x97b2, calculated=0xc4cb`), correctly logged as `crc_mismatch` with `status: "partial"`.

---

### 2.3 VAULT (School Office Multi-Entry Archive Container)
* **Magic:** `VLT1` (`56 4C 54 31`) at offset `0x00`.
* **Header Layout (16 bytes, Little-Endian):**
  - `0x00..0x03`: `VLT1`
  - `0x04..0x05`: `entry_count` (uint16 LE)
  - `0x06`: `xor_key` (uint8) — Obfuscation key byte (e.g. `252` in `s09.dat`)
  - `0x07`: `flags` (uint8) — Flags byte
  - `0x08..0x09`: `reserved` (2 bytes)
  - `0x0A..0x0B`: `flags_extended` (uint16 LE)
  - `0x0C..0x0F`: `index_offset` (uint32 LE)
* **Entry Name Table & Obfuscated Length Un-masking:**
  - In standard VAULT files (`s08.dat`, `s10.dat`), entry names are stored as `n_len` (uint8) + ASCII characters.
  - In obfuscated VAULT files (`s09.dat`), the `n_len` prefix is itself obfuscated with `xor_key`:
    $$\text{n\_len} = \text{raw\_byte} \oplus \text{xor\_key}$$
    If `raw_byte > max_possible_len` and $(\text{raw\_byte} \oplus \text{xor\_key}) \le \text{max_possible_len}$, the unmasked length is utilized.
  - Un-obfuscated names are clean strings (`"edge.bin"`, `"icon.bmp8"`, `"unicode.txt"`).
* **Decryption Scheme:**
  - Names and text payload bytes use a rolling XOR cipher:
    $$\text{byte}_j \oplus ((\text{xor\_key} + j) \pmod{256})$$
  - Raw binary (`.bin`) blobs remain unencrypted.
* **Index Table (16 bytes per entry at end of file):**
  - `id` (uint16 LE), `type` (1B), `flags` (1B), `name_pos` (uint32 LE), `blob_offset` (uint32 LE), `stored_size` (uint16 LE), `decoded_size` (uint16 LE).
* **Blobs:** Begin with marker `b"BL"` + `id` (uint16 LE) followed by compressed/raw data.
* **Hash:** Computes SHA-256 of decoded payload bytes.

---

### 2.4 Lotus 1-2-3 WKS (Spreadsheet Cell TLV Stream)
* **BOF Record:** Opcode `0x0000`, Length `0x0002`, Version `0x0404` (Lotus 1-2-3 Release 1A).
* **Record Framing:** Opcode (uint16 LE) + Length (uint16 LE) + Body (`Length` bytes).
* **Cell Opcode Types:**
  - `0x000C (BLANK)`: format (1B), col (uint16 LE), row (uint16 LE).
  - `0x000D (INTEGER)`: format (1B), col (uint16 LE), row (uint16 LE), value (int16 LE).
  - `0x000E (NUMBER)`: format (1B), col (uint16 LE), row (uint16 LE), value (float64 IEEE-754 LE).
  - `0x000F (LABEL)`: format (1B), col (uint16 LE), row (uint16 LE), prefix char (`'` left, `"` right, `^` center, `\` repeat) + null-terminated CP437 string.
  - `0x0010 (FORMULA)`: format (1B), col (uint16 LE), row (uint16 LE), cached float (float64 LE), bytecode length (uint16 LE at `payload[13:15]`), raw formula hex string (`payload[15:]`).
  - `0x0008 (COLWIDTH)`: col (uint16 LE), width (uint8).
  - `0x0001 (EOF)`: Terminates worksheet.

---

### 2.5 Commodore 64 GEOS Convert CVT (Disk Image Container)
* **Signature:** ASCII `PRG formatted GEOS file` or `SEQ formatted GEOS file` within first 64 bytes, or byte 0 equals `0x83`.
* **Block Layout:** 254-byte sequential blocks (C64 256B disk sectors with link bytes stripped).
* **Block 1 GEOS Info Block:**
  - Filename, structure (`seq` or `vlir`), GEOS file type, modified timestamp (`YYYY-MM-DDTHH:MM`), class name, author, description.
* **Character Set:** Commodore PETSCII to ASCII mapping (`0xC1..0xDA` -> `A..Z`, `0x41..0x5A` -> `a..z`, `0x0D` -> `\n`).

---

### 2.6 IBM Mainframe EBCDIC Dump (`EBCDIC-DUMP`)
* **Identification:** EBCDIC CP037 header text (e.g. `STUDENT EXTRACT`, header record code `0xC8`).
* **Framing Modes:**
  1. **Unblocked Mode (RDW only):**
     - 4-byte Record Descriptor Word: 2 bytes big-endian length + 2 bytes zeros.
  2. **Variable Blocked Mode (BDW + RDW):**
     - Outer 4-byte Block Descriptor Word: 2 bytes big-endian block length + 2 bytes zeros.
     - Inner 4-byte Record Descriptor Word: 2 bytes big-endian record length + 2 bytes zeros.
* **Record Formats:**
  - `H` (Header): Title, Run Date (`YYYY-MM-DD`).
  - `D` (Detail): `student_id` (6B), `name` (20B), `dob` (5B IBM COMP-3 packed decimal), `gpa` (3B COMP-3 decimal), `credits` (uint16 BE), `status` (1B), `balance` (4B signed COMP-3 decimal).
  - `T` (Trailer): `trailer_count`, `trailer_credits_total`.

---

### 2.7 WordPerfect WPD (Document Stream)
* **Magic:** `\xFFWPC` (`FF 57 50 43`) at offset `0x00`.
* **Header:** Offset `0x04` contains pointer to document area.
* **Stream Parsing:** Filters multi-byte control functions (`0xD0..0xFF`) and single-byte codes, extracting clean paragraph and page break (`0x0C`) text records.

---

### 2.8 Xerox Alto Bravo (Research Lab Editor Document)
* **Delimiters:** Plain ASCII paragraphs delimited by Carriage Return (`\r` / `0x0D`).
* **Trailer:** Text body terminates at `0x1A` (CTRL-Z), followed by formatting property runs (start, length, looks, font) up to end of file.

---

### 2.9 Doom WAD Archive (Game Data)
* **Magic:** `PWAD` or `IWAD` (4 bytes).
* **Header Layout (12 bytes, Little-Endian):** `magic` (4B), `num_lumps` (int32), `dir_offset` (int32).
* **Lump Records:** 16 bytes per directory entry (`offset (int32)`, `size (int32)`, `name (8B null-padded ASCII)`), with SHA-256 computation over payloads.

---

### 2.10 Quake PAK Archive (Game Data)
* **Magic:** `PACK` (4 bytes).
* **Header Layout (12 bytes, Little-Endian):** `magic` (4B), `dir_offset` (int32), `dir_length` (int32).
* **Directory Entries:** 64 bytes per entry (`name (56B null-padded ASCII)`, `offset (int32)`, `size (int32)`), with SHA-256 computation over entry payloads.

---

## 3. Damage Taxonomy & Status Mapping (OUTPUT-CONTRACT.md)

* **Status Values:**
  - `ok`: Clean file with zero lost or unverified records.
  - `partial`: Recovered records with partial fields, truncation, or skipped unparsed bytes.
  - `unsupported`: Recognized format that cannot be decoded (e.g. unknown encryption).
  - `unrecognized`: Unrecognized format or foreign file signature.
  - `failed`: Recognized format with unrecoverable header damage.

* **Damage `kind` Vocabulary:**
  `truncated`, `crc_mismatch`, `checksum_mismatch`, `bad_length`, `unparsed_bytes`, `count_mismatch`, `invalid_value`, `oob_pointer`, `index_missing`, `header_checksum`, `encrypted`, `unknown_record`.
