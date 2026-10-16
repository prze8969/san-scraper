# TODO.md: Prioritized Backlog & Safe Verification Commands

## Prioritized Open Work

| Priority | Task Description | Affected Files | Verification Command |
| :--- | :--- | :--- | :--- |
| **P1** | **Ground-Truth Calibration for LIBRA-98, LABLOG, VAULT:** If official ground-truth binary samples or evaluation schemas become available, audit and calibrate the provisional parsers to match external judge expectations. | `src/formats/libra98.py`, `src/formats/lablog.py`, `src/formats/vault.py`, `FORMAT-SPEC.md` | `python -m unittest discover tests` |
| **P2** | **ZIP Data Descriptor Stream Parser (Bit 3):** Support streaming ZIP files created without seekable sizes in local headers where bit 3 is set by scanning for trailing `0x08074b50` signatures. | `src/formats/zip.py`, `tests/test_known_formats.py` | `python -m unittest tests/test_known_formats.py` |
| **P3** | **Additional Documented Legacy Formats:** Add parsers for well-documented formats: TAR (POSIX ustar header layout) and BMP (BITMAPFILEHEADER / BITMAPINFOHEADER). | `src/formats/tar.py` (new), `src/detector.py`, `src/engine.py`, `tests/test_known_formats.py` | `python -m unittest discover tests` |
| **P4** | **Multi-Stream GZIP Decompression:** Support concatenated `.gz` member streams (RFC 1952 section 2.2) by iterating member headers sequentially until EOF. | `src/formats/gzip.py`, `tests/test_known_formats.py` | `python -m unittest tests/test_known_formats.py` |
| **P5** | **Lotus 1-2-3 Formula Bytecode Disassembler:** Provide human-readable formula text (e.g. `+A1+B1`) from Lotus formula bytecode (`0x0010`) while keeping evaluation inert. | `src/formats/wks.py`, `tests/test_wks.py` | `python -m unittest tests/test_wks.py` |

---

## Safe Verification Routine
Whenever making any changes to the codebase, run this sequential validation pipeline:
```powershell
# 1. Run unit test suite (must report 93 tests, 0 failures, 0 errors)
python -m unittest discover tests

# 2. Run end-to-end synthetic demo
.\demo\run_demo.bat

# 3. Test CLI on a single file with verbose probes
.\salvage.bat demo\input\12_valid.wad demo\output_test --verbose
```
