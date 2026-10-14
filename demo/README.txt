# DEMO FIXTURES (SYNTHETIC)

All test files in demo/input/ are SYNTHETIC fixtures generated using the project's internal test builders based on documented specifications and provisional contracts:

1. 01_valid.lib (LIBRA-98): Synthetic binary file adhering to provisional LIBRA-98 32-byte header and 48-byte record layout.
2. 02_valid.lab (LABLOG): Synthetic binary journal adhering to provisional LABLOG 24-byte header and BLOK frames with per-block CRC32.
3. 03_valid.vlt (VAULT): Synthetic binary archive adhering to provisional VAULT layout with central index, PackBits RLE compression, and XOR deobfuscation.
4. 04_valid.pak (Quake PAK): Synthetic game archive adhering to id Software Quake PAK v1 format (12-byte header, 64-byte directory entries).
5. 05_valid.wks (Lotus 1-2-3 Release 1A): Synthetic spreadsheet stream adhering to Lotus 1-2-3 Release 1A record layout (BOF 0x0404, BLANK, INTEGER, NUMBER, LABEL, FORMULA, EOF).
6. 06_truncated.pak: Synthetic PAK archive truncated midway through the directory table (exercises defensive truncation handling and damage logging).
7. 07_corrupted_block.lab: Synthetic LABLOG file with deliberate CRC32 mismatch in block 1 (demonstrates block damage isolation, recovery of surrounding blocks, and resynchronization).
8. 08_unknown.bin: Arbitrary binary stream not matching any recognized magic signature (exercises graceful fallback without crash).
