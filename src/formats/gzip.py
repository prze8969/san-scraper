"""Integrity parser for GZIP format (RFC 1952).

Specification:
  Header (10 bytes minimum):
    0x00..0x02: Magic 0x1F, 0x8B
    0x02: Compression method (8 = deflate)
    0x03: Flags (FTEXT, FHCRC, FEXTRA, FNAME, FCOMMENT)
    0x04..0x08: Modification time (uint32)
    0x08: Extra flags
    0x09: Operating system
  Payload: Deflate compressed stream
  Trailer (8 bytes):
    CRC-32 (uint32, little-endian) of uncompressed data
    ISIZE (uint32, little-endian) size modulo 2^32
"""

from __future__ import annotations
import gzip
import struct
import zlib
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader, BoundsError
from src.models import (
    FileRecoveryResult,
    RecoveredRecord,
    RecordStatus,
    DamageBlock,
    DamageType,
)

class GzipParser(BaseParser):
    """Defensive GZIP parser verifying headers, deflate stream, and trailer CRC-32/ISIZE."""

    MAGIC = b"\x1f\x8b"
    HEADER_SIZE = 10
    MAX_DECOMPRESS = 32 * 1024 * 1024  # 32 MB cap

    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        file_size = reader.size
        damages: list[DamageBlock] = []
        recovered_records: list[RecoveredRecord] = []
        is_valid_header = False

        if file_size < self.HEADER_SIZE + 8:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=file_size,
                    damage_type=DamageType.TRUNCATION,
                    description=f"File smaller than minimum GZIP boundary ({file_size} < 18)",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="GZIP",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                damages=damages,
            )

        data = reader.peek_bytes(file_size)
        if data[:2] != self.MAGIC:
            damages.append(
                DamageBlock(
                    offset=0,
                    length=2,
                    damage_type=DamageType.UNKNOWN_SIGNATURE,
                    description=f"Invalid GZIP magic: {data[:2].hex()}",
                )
            )
            return FileRecoveryResult(
                filename=filename,
                format_name="GZIP",
                file_size=file_size,
                is_valid_header=False,
                total_records=0,
                damages=damages,
            )

        is_valid_header = True
        method = data[2]
        flags = data[3]
        mtime = struct.unpack_from("<I", data, 4)[0]

        # Read optional header fields (FEXTRA, FNAME, FCOMMENT, FHCRC)
        pos = 10
        orig_filename = ""
        try:
            if flags & 0x04:  # FEXTRA
                xlen = struct.unpack_from("<H", data, pos)[0]
                pos += 2 + xlen
            if flags & 0x08:  # FNAME
                name_end = data.find(b"\x00", pos)
                if name_end != -1:
                    orig_filename = data[pos:name_end].decode("latin-1", errors="replace")
                    pos = name_end + 1
            if flags & 0x10:  # FCOMMENT
                comm_end = data.find(b"\x00", pos)
                if comm_end != -1:
                    pos = comm_end + 1
            if flags & 0x02:  # FHCRC
                pos += 2
        except Exception:
            damages.append(
                DamageBlock(
                    offset=10,
                    length=pos - 10,
                    damage_type=DamageType.INVALID_HEADER,
                    description="Malformed optional GZIP header fields",
                )
            )

        # Decompress payload and check trailer
        rec_status = RecordStatus.COMPLETE
        errors: list[str] = []
        trailer_crc = None
        trailer_isize = None
        calc_crc = None
        decompressed_bytes = None

        if file_size >= 8:
            trailer_crc, trailer_isize = struct.unpack("<II", data[-8:])

        try:
            # First try decompressing the stream with header (16 + MAX_WBITS)
            try:
                decompressed_bytes = zlib.decompress(data, 16 + zlib.MAX_WBITS, self.MAX_DECOMPRESS)
            except Exception:
                # If pos was advanced past optional headers, decompress raw deflate payload
                end_payload = file_size - 8 if file_size >= 8 else file_size
                decompressed_bytes = zlib.decompress(data[pos:end_payload], -15, self.MAX_DECOMPRESS)
            calc_crc = zlib.crc32(decompressed_bytes) & 0xFFFFFFFF
            if trailer_crc is not None and calc_crc != trailer_crc:
                rec_status = RecordStatus.CORRUPTED
                err_msg = f"CRC-32 mismatch: trailer 0x{trailer_crc:08X}, computed 0x{calc_crc:08X}"
                errors.append(err_msg)
                damages.append(
                    DamageBlock(
                        offset=file_size - 8,
                        length=4,
                        damage_type=DamageType.CHECKSUM_MISMATCH,
                        description=err_msg,
                    )
                )
        except Exception as e:
            rec_status = RecordStatus.CORRUPTED
            err_msg = f"GZIP decompression failed: {str(e)}"
            errors.append(err_msg)
            damages.append(
                DamageBlock(
                    offset=pos,
                    length=max(0, file_size - pos - 8),
                    damage_type=DamageType.DECOMPRESSION_ERROR,
                    description=err_msg,
                )
            )

        rec_name = orig_filename or (filename.rsplit(".gz", 1)[0] if filename.endswith(".gz") else f"{filename}.unpacked")
        rec_fields = {
            "name": rec_name,
            "orig_filename": orig_filename,
            "mtime": mtime,
            "compressed_size": file_size - pos - 8 if file_size >= pos + 8 else 0,
            "uncompressed_size": len(decompressed_bytes) if decompressed_bytes is not None else trailer_isize,
            "crc_status": "verified" if (calc_crc == trailer_crc and calc_crc is not None) else "mismatch",
        }
        if decompressed_bytes is not None:
            rec_fields["decompressed_data"] = decompressed_bytes

        recovered_records.append(
            RecoveredRecord(
                record_id=0,
                status=rec_status,
                byte_range=(pos, max(pos, file_size - 8)),
                fields=rec_fields,
                errors=errors,
            )
        )

        return FileRecoveryResult(
            filename=filename,
            format_name="GZIP",
            file_size=file_size,
            is_valid_header=is_valid_header,
            total_records=1,
            recovered_records=recovered_records,
            damages=damages,
            metadata={
                "mtime": mtime,
                "orig_filename": orig_filename,
                "trailer_crc": f"0x{trailer_crc:08X}" if trailer_crc is not None else None,
                "trailer_isize": trailer_isize,
            },
        )
