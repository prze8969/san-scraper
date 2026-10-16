# FORMAT-SPEC: Authoritative Binary Format Specifications & Defensive Parsing Rules

This document specifies the exact byte structures, field types, decoding algorithms, and defensive recovery rules verified and calibrated against the official Problem Statement 02 Participant Kit (`Genesis_Track3_PS2_Sample_Files-main/`).

---

## 1. Defensive Parsing & Architectural Invariants

All format recovery modules in `salvage` adhere strictly to these invariants:
1. **Never Crash (Exit Code 0):** Unhandled exceptions are caught at the engine boundary and mapped to `status: "failed"` or `"unrecognized"`.
2. **Memory Safety:** Buffer allocations are strictly bounded by `min(declared_size, remaining_file_bytes)`. Decompression routines cap output at 16 MB.
3. **Resynchronization:** In continuous streams (e.g. `LIBRA-98`, `LABLOG`, `WKS`), damaged byte spans are recorded as `unparsed_bytes` while scanning forward to the next valid record sync boundary.
4. **Offline & Zero Dependencies:** Operates using 100% standard Python 3.10+ library modules (`struct`, `json`, `hashlib`, `datetime`).
5. **Strict Schema Compliance:** All outputs conform to [OUTPUT-CONTRACT.md](file:///e:/san%20scarper/san-scraper/Genesis_Track3_PS2_Sample_Files-main/OUTPUT-CONTRACT.md).

---

## 2. Format Specifications (10 Formats)

### 2.1 LIBRA-98 (Library Database)
* **Magic:** `LB98` (`4C 42 39 38`) at offset 0x00.
* **Header Layout (16 bytes):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | `magic` | 4 bytes | `b"LB98"` |
  | 0x04 | `version` | uint16 LE | Format version |
  | 0x06 | `declared_count` | uint16 LE | Declared total record count |
  | 0x08 | `dos_date` | uint16 LE | Creation date: `Y = ((val >> 9) & 0x7F) + 1980`, `M = (val >> 5) & 0xF`, `D = val & 0x1F` |
  | 0x0A | `dos_time` | uint16 LE | Creation time: `H = (val >> 11) & 0x1F`, `M = (val >> 5) & 0x3F`, `S = (val & 0x1F) * 2` |
  | 0x0C | `data_offset` | uint16 LE | Offset to first record (typically 16) |
  | 0x0E | `branch_id` | uint16 LE | Library branch identifier |
* **Record Structure:**
  - `0x00`: Sync marker `0xA5` (1 byte).
  - `0x01`: `rec_len` (1 byte) - Length of record payload following this byte.
  - `0x02`: `flags` (1 byte) - `0x01`: checked_out, `0x02`: deleted, `0x04`: reference_only.
  - `+0x00`: `id` (uint32 LE).
  - `+0x04`: `title_len` (1 byte) + `title` (CP437 string).
  - `+idx`: `author_len` (1 byte) + `author` (CP437 string).
  - `+idx`: `year_raw` (uint16 LE) - Year calculated as `year_raw + 1500`.
  - `+idx`: `price_cents` (uint16 LE).
  - `+idx`: `copies` (uint8).
  - `+idx`: `isbn` (10 bytes ASCII).
  - If `checked_out`: `due_date` (uint16 LE DOS Date formatted as `YYYY-MM-DD`).
* **Trailer:** `END!` marker terminates the record stream.

---

### 2.2 LABLOG (Laboratory Journal & Sensor Stream)
* **Magic:** `LLOG` (`4C 4C 4F 47`) at offset 0x00.
* **Header Layout (36 bytes + channels):**
  | Offset | Field | Type | Description |
  | :--- | :--- | :--- | :--- |
  | 0x00 | `magic` | 4 bytes | `b"LLOG"` |
  | 0x04 | `version` | uint8 | Format version |
  | 0x05 | `num_channels`| uint8 | Number of sensor channels |
  | 0x06 | `interval_raw`| uint16 LE | Sample interval (multiplied by 10 to obtain ms) |
  | 0x08 | `instrument` | 16 bytes | ASCII instrument model string (null-padded) |
  | 0x18 | `start_ts` | uint32 LE | Start timestamp in seconds from 1990-01-01 00:00:00 UTC |
  | 0x1C | `block_count` | uint16 LE | Declared block count |
  | 0x1E | `reserved` | 6 bytes | Padding |
* **Channel Descriptors (12 bytes per channel starting at offset 36):**
  - Unit: 4 bytes ASCII.
  - Slope ($m$): float32 LE.
  - Intercept ($b$): float32 LE.
* **Followed by:** 2-byte header CRC16.
* **Blocks (Prefixed by `0xB1`):**
  - `Type 1 (DATA)`: `start_sample` (uint16 LE), `count` (uint8), raw sensor values (int16 LE per channel). Calibrated value = `round(raw * slope + intercept, 4)`. Dropouts (`-32768` or `32767`) emit `null`.
  - `Type 2 (EVENT)`: `sample` (uint16 LE), `severity` (uint8), `len` (uint8), `message` (ASCII).

---

### 2.3 VAULT (Encrypted Container Archive)
* **Magic:** `VLT1` (`56 4C 54 31`) at offset 0x00.
* **Header Layout (16 bytes):**
  - `0x00`: `magic` (4B `VLT1`).
  - `0x04`: `entry_count` (uint16 LE).
  - `0x06`: `xor_key` (uint16 LE).
  - `0x08`: `reserved` (2 bytes).
  - `0x0A`: `flags` (uint16 LE).
  - `0x0C`: `index_offset` (uint32 LE) - Offset to name string table and index table.
* **Decryption Scheme:**
  - Names and text blob payloads are encrypted with a rolling XOR cipher:
    $$\text{byte}_j \oplus ((\text{xor\_key} + j) \pmod{256})$$
  - Raw binary (`.bin`) blobs remain unencrypted.
* **Index Table:** 16 bytes per entry at end of file:
  - `id` (uint16 LE), `type` (1B), `flags` (1B), `name_pos` (uint32 LE), `blob_offset` (uint32 LE), `stored_size` (uint16 LE), `decoded_size` (uint16 LE).
* **Blobs:** Begin with `b"BL"` + `id` (uint16 LE) followed by payload.

---

### 2.4 WKS (Lotus 1-2-3 Spreadsheet)
* **BOF Record:** Opcode `0x0000`, Length `0x0002`, Version `0x0404` (Release 1A).
* **Record Structure:** Opcode (uint16 LE) + Length (uint16 LE) + Payload.
* **Cell Types:**
  - `0x000D (INTEGER)`: format (1B), col (uint16 LE), row (uint16 LE), value (int16 LE).
  - `0x000E (NUMBER)`: format (1B), col (uint16 LE), row (uint16 LE), value (float64 LE).
  - `0x000F (LABEL)`: format (1B), col (uint16 LE), row (uint16 LE), prefix char (`'` left, `"` right, `^` center, `\` repeat) + null-terminated CP437 string.
  - `0x0010 (FORMULA)`: format (1B), col (uint16 LE), row (uint16 LE), cached float (float64 LE), bytecode length (uint16 LE at payload[13:15]), raw formula bytecode bytes (`payload[15:]`).
  - `0x000C (BLANK)`: format (1B), col (uint16 LE), row (uint16 LE).
  - `0x0008 (COLWIDTH)`: col (uint16 LE), width (uint8).
  - `0x0001 (EOF)`: Terminates spreadsheet.

---

### 2.5 CVT (Commodore 64 GEOS Convert Disk Image)
* **Identification:** ASCII `PRG formatted GEOS file` within the first 64 bytes or GEOS header signature `0x83`.
* **Block Layout:** 254-byte sequential blocks (C64 256-byte track/sector links stripped).
* **Info Block (Block 1):**
  - Filename, structure (`seq` or `vlir`), GEOS file type, modified timestamp (`YYYY-MM-DDTHH:MM`), class name, author, and description.
* **Character Set:** Commodore PETSCII to ASCII conversion:
  - Uppercase: `0xC1..0xDA -> A..Z`.
  - Lowercase: `0x41..0x5A -> a..z`.
  - Newlines: `0x0D -> \n`.
* **Scraping:** Extracts records per slot across sequential text and VLIR record chains.

---

### 2.6 EBCDIC-DUMP (IBM Mainframe Tape Record Dump)
* **Identification:** CP037 EBCDIC text (e.g. `STUDENT EXTRACT`, header record code `0xC8`).
* **Record Delimitation:** 4-byte Record Descriptor Word (RDW):
  - 2 bytes big-endian length + 2 bytes zeros.
* **Encoding & Field Layout:**
  - Header Record: Title, Run Date (`YYYY-MM-DD`).
  - Detail Records: `student_id` (ASCII), `name` (CP037), `dob` (IBM COMP-3 packed decimal `YYYY-MM-DD`), `gpa` (COMP-3 decimal `X.XX`), `credits` (uint16 BE), `status` (CP037), `balance` (signed COMP-3 decimal).
  - Trailer Record: `trailer_count`, `trailer_credits_total`.
* **COMP-3 Packed Decimal:** Nibbles store BCD digits; final nibble denotes sign (`0xC`/`0xF` = positive, `0xD` = negative).

---

### 2.7 WPD (WordPerfect Document)
* **Magic:** `\xFFWPC` (`FF 57 50 43`) at offset 0x00.
* **Document Structure:** Document header points to document text stream.
* **Record Extraction:**
  - Extracts paragraphs and page breaks (`0x0C`).
  - Strips inline multi-byte control codes (`0xC0..0xFF`) to salvage clean text.

---

### 2.8 BRAVO (Xerox Alto Bravo Document)
* **Structure:** Text paragraphs delimited by Carriage Return (`\r` / `0x0D`).
* **Trailer Format Runs:** Text stream terminates at `0x1A`, followed by binary formatting property runs.
* **Record Extraction:**
  - Emits records for each non-empty text paragraph.
  - Extracts format runs (start, length, looks, font) into metadata.

---

### 2.9 WAD (Doom Archive)
* **Magic:** `PWAD` or `IWAD` (4 bytes).
* **Header:** `magic` (4B), `num_lumps` (uint32 LE), `dir_offset` (uint32 LE).
* **Lump Records:** 16 bytes per entry in directory:
  - `offset` (uint32 LE), `size` (uint32 LE), `name` (8 bytes null-padded ASCII).
  - Computes SHA-256 of lump payloads.

---

### 2.10 PAK (Quake Archive)
* **Magic:** `PACK` (4 bytes).
* **Header:** `magic` (4B), `dir_offset` (uint32 LE), `dir_length` (uint32 LE).
* **Directory Entries:** 64 bytes per entry:
  - `name` (56 bytes null-padded ASCII), `offset` (uint32 LE), `size` (uint32 LE).
  - Computes SHA-256 of entry payloads.

---

## 3. Damage Vocabulary & Status Mapping

Conforms strictly to `OUTPUT-CONTRACT.md`:
* **Statuses:** `ok`, `partial`, `unsupported`, `unrecognized`, `failed`.
* **Damage Kinds:**
  - `truncated`: File ends before declared length or expected boundary.
  - `crc_mismatch`: CRC verification failed.
  - `checksum_mismatch`: Additive or modular checksum failed.
  - `bad_length`: Field length violates structural alignment or bounds.
  - `unparsed_bytes`: Garbage bytes skipped between valid sync markers.
  - `count_mismatch`: Number of parsed records does not equal declared count.
  - `invalid_value`: Sentinel or illegal value detected.
  - `oob_pointer`: Offset pointer exceeds file size.
  - `index_missing`: Directory table corrupted or absent.
  - `header_checksum`: Header validation failed.
  - `encrypted`: Encrypted content without key.
  - `unknown_record`: Unrecognized record opcode.
