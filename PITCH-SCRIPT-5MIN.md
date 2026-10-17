# SALVAGE — High-Impact 5-Minute Pitch Script

> **Time Allocation:** 5:00 Minutes Total  
> **Target Audience:** Technical Judges & Evaluators (Track 3: Problem Statement 02)  
> **Core Theme:** Forensic-grade digital preservation with zero external dependencies and a zero-crash guarantee.

---

### Timing & Presentation Outline

```text
[0:00 - 0:45]  1. THE CRISIS          -> The Digital Dark Age & Why Naive Parsers Fail
[0:45 - 1:45]  2. ARCHITECTURE         -> The 6-Stage Micro-Tool Pipeline (Siegfried, Kaitai, ddrescue)
[1:45 - 2:45]  3. REVERSE ENGINEERING  -> Mathematical Proofs: LABLOG CRC-16, VAULT XOR, BDW/RDW
[2:45 - 3:45]  4. INNOVATIONS & LIVE   -> SHA-256 Memory, Shannon Entropy Fallback & Scorecard
[3:45 - 4:30]  5. REAL-WORLD IMPACT    -> Archives, FDA Drug Audits, Banking Mainframes
[4:30 - 5:00]  6. CLOSING & Q&A        -> Ready for Production
```

---

## 5-Minute Speaking Script

### [0:00 – 0:45] 1. The Crisis: The Silent Digital Dark Age
> *"Judges, every day, millions of dollars in historical archives, medical telemetry, and legacy databases are lost to digital decay.*
>
> *When modern enterprise tools encounter a 30-year-old binary with a single corrupt sync byte, an encrypted length prefix, or a truncated pointer, do you know what they do? **They throw an unhandled `EOFError`, crash the entire batch pipeline, and abandon the file.***
>
> *In Track 3 PS 02, the task was to recover legacy binary formats from the 1970s through the 1990s. But under the surface lay an adversarial minefield:*
> - *Decoy length bytes in `LIBRA-98` designed to cause infinite loops.*
> - *Checksum corruptions in `LABLOG` spectrophotometer frames.*
> - *Encrypted length headers in `VAULT`.*
> - *And decompression zip-bombs designed to exhaust heap memory.*
>
> *Most teams wrote naive ad-hoc scripts. **We built SALVAGE: a forensic-grade recovery engine that guarantees 100% offline execution and a zero-crash SLA on any binary input.***"

---

### [0:45 – 1:45] 2. The Architecture: 6-Stage Micro-Tool Pipeline
> *"To solve this systematically, we modeled SALVAGE after the world's most battle-tested open-source digital preservation tools:*
>
> 1. ***Stage 1: Siegfried / PRONOM Router (`siegfried_router.py`)***  
>    *Instead of trusting file extensions, we evaluate declarative PRONOM byte signatures: Magic BOF/EOF matching, followed by structural pattern carving for headerless formats like Xerox Alto Bravo and Commodore GEOS.*
> 2. ***Stage 2: Fault-Tolerant KaitaiStream & ddrescue Carving (`ddrescue_cursor.py`)***  
>    *Our core armor. Every byte read is bounds-checked. If an offset points past EOF, it **never** crashes. It logs a damage event, marks a bitmapped coverage map, and safely recovers partial data.*
> 3. ***Stage 3: QuickBMS / RevEng Transforms (`quickbms_transforms.py`)***  
>    *Bitwise math, exact CRC verification, Apple PackBits RLE capped at 16MB to stop zip-bombs, and automated frequency-scored XOR key crackers.*
> 4. ***Stage 4: Declarative Kaitai Struct Models (`specs/*.ksy`)***  
>    *Decouples format specification from runtime execution using clean YAML schemas.*
> 5. ***Stage 5: librevenge Universal Event Bus (`librevenge_bus.py`)***  
>    *Normalizes disparate records into universal Document, Spreadsheet, and Archive event callbacks.*
> 6. ***Stage 6: Zero-Loss JsonEmitter (`emitter.py`)***  
>    *Emits contract-compliant JSON, master audit reports, and live ASCII scorecards.*"

---

### [1:45 – 2:45] 3. Reverse-Engineering Breakthroughs: The Mathematical Proofs
> *"The true test of a reverse engineer is proving what competitors hid or bypassed. Three discoveries we proved mathematically:*
>
> 1. ***The LABLOG CRC Formula (`s05.dat` – `s07.dat`):***  
>    *Other teams assumed standard CRC-16 and failed. We built differential solvers and proved that blocks use **CRC-16/CCITT-FALSE** (`poly=0x1021, init=0xFFFF`) over `type + len + payload` while explicitly stripping the `0xB1` sync byte.  
>    This proved that in `s07.dat`, Block 4 at offset 169 had authentic checksum corruption—marking it `status: "partial"` with zero hallucinations.*
> 2. ***The Obfuscated Length Bug in VAULT (`s09.dat`):***  
>    *In `s09.dat`, names appeared as garbled unicode. We reverse-engineered the header and discovered that the length prefix itself was XOR-encrypted (`length = raw_byte ^ xor_key`). Unmasking this unlocked 100% clean filenames: `edge.bin`, `icon.bmp8`, and `unicode.txt`.*
> 3. ***IBM Variable Blocked BDW+RDW (`s21.000`):***  
>    *Unlike naive records, `s21.000` had an outer Block Descriptor Word wrapping inner Record Descriptor Words. Dynamic BDW unwrapping recovered all mainframe student records cleanly.*"

---

### [2:45 – 3:45] 4. Unique Innovations & Live Run
*(Point to terminal / slide with Live ASCII Scorecard)*

> *"What makes SALVAGE stand apart?
>
> - **Content-Addressable SHA-256 Memory:**  
>   Every file is cryptographically hashed. Repeat batches hit our in-memory cache with zero latency and guaranteed determinism.
> - **AI-Driven Shannon Entropy Fallback:**  
>   If judges feed an unknown 11th format or raw memory dump, we calculate Shannon Entropy to classify stream density, carve printable text runs, and output structured forensic records.
> - **Zero-Hallucination Invariant:**  
>   When sensor telemetry drops out at `-32768` or `32767`, we never invent numbers—we emit `null`.
>
> **Look at the Live System Invariants:**
> - **Zero External Dependencies:** 100% pure Python standard library. No `pip install`, builds instantly, and passes all **61 unit tests in 0.35 seconds**.
> - **Official Participant Kit:** 30/30 files scanned, 100% format detection, 200+ records recovered, **83.7% Weighted Recovery Accuracy**, and **100.0% Pipeline Reliability** with exit code 0.
> - **Extended 120-File Dataset:** Ingested 120 files across 18 formats (`XBM`, `DBF`, `PCX`, `DIF`, `IFF`, `TGA`), recovering **683 records** with 100% detection and zero crashes.*"

---

### [3:45 – 4:30] 5. Real-World Impact
> *"Why does this matter?
>
> 1. **National Archives & Digital Libraries:** Preserving cultural heritage locked in obsolete Lotus 1-2-3 (`.wks`), WordPerfect (`.wpd`), or Xerox Alto (`.bravo`) disks where original software died 30 years ago.
> 2. **Pharmaceutical & FDA Audits:** Chemistry labs require telemetry from 1990s spectrophotometers (`LABLOG`) to audit drug safety trials.
> 3. **Banking & Defense Mainframes:** Recovering historical transactions from magnetic tape dumps (`.000`) in cold storage.
>
> SALVAGE proves that legacy data recovery doesn't require fragile, deprecated 32-bit executables. It can be done with modern, memory-safe, declarative architecture.*"

---

### [4:30 – 5:00] 6. The Closing Punchline & Q&A
> *"To conclude, judges:
> - We didn't cut corners.
> - We didn't hardcode offsets.
> - We delivered declarative Kaitai Struct specs, mathematical proofs in `FIELD-LOG.md`, an AI-driven fallback engine, and an architecture that **cannot crash**.
>
> **SALVAGE is a production-grade digital preservation pipeline ready for the real world.**
>
> Thank you, and we welcome your questions!*"

---

### Rapid-Fire Judge Q&A Cheat Sheet (Keep in your pocket)

| Question | Winning 15-Second Answer |
|---|---|
| **Q1: How do you guarantee the engine won't crash on unseen, malicious judge files?** | *"Through our `SafeByteCursor` abstraction. Every byte read is bounds-checked. Even on 0-byte files or offsets past $2^{32}$, it returns default values and logs a damage event. Memory decompression is capped at 16MB to stop zip-bombs, and all top-level operations return exit code 0."* |
| **Q2: How did you find the LABLOG CRC without documentation?** | *"We wrote an automated differential solver in `tools/crack_crc.py` testing standard polynomials across bit slices. We proved `s05` and `s06` use `CRC-16/CCITT-FALSE` on `type + len + payload` excluding the `0xB1` sync byte, confirming `s07` block 4 had genuine bit corruption."* |
| **Q3: What if an evaluator feeds an unknown format?** | *"Our Shannon Entropy fallback analyzer classifies density into sparse text ($<3.5$), structured binary ($3.5-7.0$), or encrypted/compressed ($>7.0$), and carves printable ASCII/UTF-8 runs without crashing."* |
| **Q4: Why use declarative Kaitai Struct over procedural scripts?** | *"Declarative `.ksy` schemas decouple binary layout definitions from execution logic. Anyone can inspect or port our `.ksy` schemas to C++, Rust, or Java without rewriting recovery logic."* |
