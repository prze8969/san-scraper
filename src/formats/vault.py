"""Provisional parser for VAULT archive format with index table, bounded RLE, and XOR deobfuscation."""

from __future__ import annotations
import zlib
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError, TruncationError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class DecompressionError(Exception):
    pass

def bounded_rle_decompress(data: bytes, max_output_size: int = 16 * 1024 * 1024) -> bytes:
    """
    Decompresses a PackBits/Byte-Run RLE stream with bounded output limit.
    Control byte B:
      0 <= B <= 127: literal run of B + 1 bytes
      128: no-op / padding
      129 <= B <= 255: repeat next byte (257 - B) times
    """
    out = bytearray()
    i = 0
    in_len = len(data)

    while i < in_len:
        b = data[i]
        i += 1

        if b <= 127:
            # Literal run of b + 1 bytes
            run_len = b + 1
            if i + run_len > in_len:
                raise DecompressionError(f"RLE literal run of {run_len} bytes exceeds input stream ({in_len - i} left)")
            if len(out) + run_len > max_output_size:
                raise DecompressionError(f"RLE decompressed size exceeded limit of {max_output_size} bytes")
            out.extend(data[i:i + run_len])
            i += run_len
        elif b == 128:
            # No-op / skip
            continue
        else:
            # Repeated byte run of (257 - b)
            run_len = 257 - b
            if i >= in_len:
                raise DecompressionError("RLE repeat run missing target byte")
            repeat_byte = data[i]
            i += 1
            if len(out) + run_len > max_output_size:
                raise DecompressionError(f"RLE decompressed size exceeded limit of {max_output_size} bytes")
            out.extend(bytes([repeat_byte]) * run_len)

    return bytes(out)

def xor_deobfuscate(data: bytes, key_byte: int) -> bytes:
    """Applies single-byte XOR deobfuscation to data."""
    if key_byte == 0:
        return data
    k = key_byte & 0xFF
    return bytes(b ^ k for b in data)

class VaultParser(BaseParser):
    """
    Defensive parser for VAULT archive format.
    
    Layout contract (PROVISIONAL - for defensive testing, bounded RLE, and XOR validation):
    Header (32 bytes):
      0x00..0x08: Magic 'VAULT\x01\x00\x00' (8 bytes)
      0x08..0x0A: Version (uint16, expected 1)
      0x0A..0x0C: Flags (uint16)
      0x0C..0x10: Entry Count (uint32)
      0x10..0x14: Index Offset (uint32)
      0x14..0x18: Index Length (uint32)
      0x18..0x1C: Header CRC32 (uint32)
      0x1C..0x20: Global XOR Key (uint32)
    
    Index Entry (48 bytes):
      +0x00: Entry ID (uint32)
      +0x04: Blob Offset (uint32)
      +0x08: Stored Size (uint32)
      +0x0C: Decoded Size (uint32)
      +0x10: Entry Flags (uint16) [bit 0: RLE, bit 1: XOR, bit 2: UTF8]
      +0x12: XOR Key Byte (uint8)
      +0x13: Reserved (uint8)
      +0x14: Entry Name (24 bytes, null-terminated)
      +0x2C: Entry CRC32 (uint32)
    """

    MAGIC = b"VAULT\x01\x00\x00"
    HEADER_SIZE = 32
    INDEX_ENTRY_SIZE = 48
    MAX_ENTRY_COUNT = 10000
    MAX_DECODED_SIZE = 16 * 1024 * 1024  # 16 MB limit per entry

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        # Step 1: Validate Header
        if file_size < self.HEADER_SIZE:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum VAULT header ({file_size} < {self.HEADER_SIZE})",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
                metadata={"status": "truncated_header"},
            )

        try:
            magic = reader.read_bytes(8)
            version = reader.read_u16_le()
            flags = reader.read_u16_le()
            declared_entries = reader.read_u32_le()
            index_offset = reader.read_u32_le()
            index_len = reader.read_u32_le()
            header_crc = reader.read_u32_le()
            global_xor_key = reader.read_u32_le()
        except BoundsError as e:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=reader.position,
                    damage_type=DamageType.INVALID_HEADER,
                    description=f"Header read failed: {str(e)}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                recovered_records=[],
                damages=damages,
            )

        if magic != self.MAGIC:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=8,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid VAULT magic: {magic.hex()}",
                )
            )
        else:
            is_valid_header = True

        # Header Checksum Check
        calc_header_crc = zlib.crc32(reader.read_exact(24, 0)) & 0xFFFFFFFF
        if header_crc != 0 and header_crc != calc_header_crc:
            damages.append(
                DamageBlock(
                    offset=0x18,
                    length=4,
                    damage_type=DamageType.CHECKSUM_MISMATCH,
                    description=f"Header CRC mismatch: declared 0x{header_crc:08X}, calculated 0x{calc_header_crc:08X}",
                )
            )

        # Step 2: Validate Index Table Offsets & Bounds
        if index_offset < self.HEADER_SIZE or index_offset > file_size:
            damages.append(
                DamageBlock(
                    offset=0x10,
                    length=4,
                    damage_type=DamageType.MALFORMED_OFFSET,
                    description=f"Index offset {index_offset} is out of file bounds [0, {file_size}]",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                file_size=file_size,
                is_valid_header=is_valid_header,
                total_records=declared_entries,
                recovered_records=[],
                damages=damages,
            )

        if index_offset + index_len > file_size:
            damages.append(
                DamageBlock(
                    offset=index_offset,
                    length=file_size - index_offset,
                    damage_type=DamageType.TRUNCATION,
                    description=f"Index table truncated (declared {index_len} bytes, available {file_size - index_offset})",
                )
            )
            index_len = max(0, file_size - index_offset)

        # Bounded entry count
        max_possible_entries = index_len // self.INDEX_ENTRY_SIZE
        entries_to_read = min(declared_entries, max_possible_entries, self.MAX_ENTRY_COUNT)

        # Read Index Entries
        raw_index_entries: list[dict] = []
        reader.seek(index_offset)
        for i in range(entries_to_read):
            entry_start = reader.position
            try:
                eid = reader.read_u32_le()
                blob_off = reader.read_u32_le()
                stored_sz = reader.read_u32_le()
                decoded_sz = reader.read_u32_le()
                eflags = reader.read_u16_le()
                xor_k = reader.read_u8()
                _pad = reader.read_u8()
                ename = reader.read_fixed_string(24)
                ecrc = reader.read_u32_le()
                raw_index_entries.append({
                    "entry_id": eid,
                    "blob_offset": blob_off,
                    "stored_size": stored_sz,
                    "decoded_size": decoded_sz,
                    "flags": eflags,
                    "xor_key": xor_k,
                    "name": ename,
                    "expected_crc": ecrc,
                    "index_entry_offset": entry_start,
                })
            except (BoundsError, TruncationError) as e:
                damages.append(
                    DamageBlock(
                        offset=entry_start,
                        length=self.INDEX_ENTRY_SIZE,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Truncated index entry {i}: {str(e)}",
                    )
                )
                break

        # Step 3: Extract and Decode Blobs Defensively
        seen_ranges: list[tuple[int, int, int]] = []  # (start, end, entry_id)

        for entry in raw_index_entries:
            eid = entry["entry_id"]
            blob_off = entry["blob_offset"]
            stored_sz = entry["stored_size"]
            decoded_sz = entry["decoded_size"]
            eflags = entry["flags"]
            xor_key = entry["xor_key"] if entry["xor_key"] != 0 else (global_xor_key & 0xFF)
            name = entry["name"]
            expected_crc = entry["expected_crc"]

            errors: list[str] = []
            rec_status = RecordStatus.COMPLETE

            # Validate Blob Offsets & Range Bounds
            if blob_off < 0 or blob_off + stored_sz > file_size:
                damages.append(
                    DamageBlock(
                        offset=entry["index_entry_offset"],
                        length=self.INDEX_ENTRY_SIZE,
                        damage_type=DamageType.MALFORMED_OFFSET,
                        description=f"Entry {eid} blob offset {blob_off} + {stored_sz} exceeds file size {file_size}",
                    )
                )
                recovered_records.append(
                    RecoveredRecord(
                        record_id=eid,
                        status=RecordStatus.UNRECOVERABLE,
                        byte_range=(blob_off, min(file_size, blob_off + stored_sz)),
                        fields={"name": name, "error": "blob_offset_out_of_bounds"},
                        errors=["Blob offset outside file bounds"],
                    )
                )
                continue

            # Check for range overlap with previous blobs
            blob_end = blob_off + stored_sz
            for prev_s, prev_e, prev_id in seen_ranges:
                if max(blob_off, prev_s) < min(blob_end, prev_e):
                    errors.append(f"Range overlap with entry {prev_id}")
            seen_ranges.append((blob_off, blob_end, eid))

            # Read Raw Stored Blob
            try:
                stored_bytes = reader.read_exact(stored_sz, blob_off)
            except BoundsError as e:
                damages.append(
                    DamageBlock(
                        offset=blob_off,
                        length=file_size - blob_off,
                        damage_type=DamageType.TRUNCATION,
                        description=f"Failed reading blob for entry {eid}: {str(e)}",
                    )
                )
                continue

            # Apply Transformations
            transformed = stored_bytes

            # 1. XOR Deobfuscation (if bit 1 set)
            if eflags & 0x02:
                transformed = xor_deobfuscate(transformed, xor_key)

            # 2. RLE Decompression (if bit 0 set)
            if eflags & 0x01:
                try:
                    target_limit = min(decoded_sz if decoded_sz > 0 else self.MAX_DECODED_SIZE, self.MAX_DECODED_SIZE)
                    decompressed = bounded_rle_decompress(transformed, max_output_size=target_limit)
                    if decoded_sz > 0 and len(decompressed) != decoded_sz:
                        errors.append(f"Decompressed size mismatch (got {len(decompressed)}, expected {decoded_sz})")
                        damages.append(
                            DamageBlock(
                                offset=blob_off,
                                length=stored_sz,
                                damage_type=DamageType.DECOMPRESSION_ERROR,
                                description=f"Entry {eid} RLE size mismatch",
                            )
                        )
                        rec_status = RecordStatus.PARTIAL
                    transformed = decompressed
                except DecompressionError as e:
                    rec_status = RecordStatus.CORRUPTED
                    err_msg = f"RLE decompression failed: {str(e)}"
                    errors.append(err_msg)
                    damages.append(
                        DamageBlock(
                            offset=blob_off,
                            length=stored_sz,
                            damage_type=DamageType.DECOMPRESSION_ERROR,
                            description=f"Entry {eid} {err_msg}",
                        )
                    )

            # Checksum Verification
            calc_crc = zlib.crc32(transformed) & 0xFFFFFFFF
            if expected_crc != 0 and expected_crc != calc_crc:
                if rec_status == RecordStatus.COMPLETE:
                    rec_status = RecordStatus.CORRUPTED
                err_crc = f"Entry CRC mismatch (declared 0x{expected_crc:08X}, calculated 0x{calc_crc:08X})"
                errors.append(err_crc)
                damages.append(
                    DamageBlock(
                        offset=blob_off,
                        length=stored_sz,
                        damage_type=DamageType.CHECKSUM_MISMATCH,
                        description=f"Entry {eid} {err_crc}",
                    )
                )

            # Text decoding if requested or printable
            text_content = None
            if eflags & 0x04 or all(32 <= b < 127 or b in (9, 10, 13) for b in transformed[:256]):
                text_content = transformed.decode("utf-8", errors="replace")

            recovered_records.append(
                RecoveredRecord(
                    record_id=eid,
                    status=rec_status,
                    byte_range=(blob_off, blob_end),
                    fields={
                        "name": name,
                        "stored_size": stored_sz,
                        "decoded_size": len(transformed),
                        "flags": eflags,
                        "is_rle_compressed": bool(eflags & 0x01),
                        "is_xor_obfuscated": bool(eflags & 0x02),
                        "text": text_content,
                    },
                    errors=errors,
                )
            )

        return FileRecoveryResult(
            filename=filename,
            format_name="VAULT",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=declared_entries,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "index_offset": index_offset if is_valid_header else None,
                "entry_count": declared_entries if is_valid_header else None,
            },
        )
