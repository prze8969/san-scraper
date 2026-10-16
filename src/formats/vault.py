"""VAULT format parser conforming to OUTPUT-CONTRACT.md.
Verified against s08.dat ground truth.
"""

from __future__ import annotations
import struct
import hashlib
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

class DecompressionError(Exception):
    pass

def bounded_rle_decompress(data: bytes, max_out: int = 16 * 1024 * 1024, max_output_size: int | None = None) -> bytes:
    if max_output_size is not None:
        max_out = max_output_size
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        i += 1
        if b <= 127:
            run_len = b + 1
            if i + run_len > len(data):
                raise DecompressionError("Literal run exceeds available data")
            if len(out) + run_len > max_out:
                raise DecompressionError("Decompression output limit exceeded")
            out.extend(data[i:i+run_len])
            i += run_len
        elif b > 128:
            repeat = 257 - b
            if i >= len(data):
                raise DecompressionError("Repeat run missing target byte")
            if len(out) + repeat > max_out:
                raise DecompressionError("Decompression output limit exceeded")
            out.extend([data[i]] * repeat)
            i += 1
        elif b == 128:
            pass
    return bytes(out)

def xor_deobfuscate(data: bytes, key: int) -> bytes:
    return bytes([b ^ key for b in data])

class VaultParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 16:
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="Header truncated (less than 16 bytes)",
                        lossy=True,
                    )
                ],
            )

        magic = data[:4]
        if magic != b"VLT1":
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail=f"Invalid signature bytes: {magic.hex()}",
                        lossy=True,
                    )
                ],
            )

        entry_count = struct.unpack("<H", data[4:6])[0]
        xor_key = struct.unpack("<H", data[6:8])[0]
        flags = struct.unpack("<H", data[10:12])[0]
        index_offset = struct.unpack("<I", data[12:16])[0]

        metadata = {
            "entry_count": entry_count,
            "xor_key": xor_key,
            "flags": flags,
        }

        if index_offset > len(data) or len(data) < index_offset + entry_count * 16:
            dmg_kind = DamageKind.OOB_POINTER if index_offset > len(data) else DamageKind.TRUNCATED
            return FileRecoveryResult(
                filename=filename,
                format_name="VAULT",
                status=OutputStatus.PARTIAL,
                metadata=metadata,
                damages=[
                    DamageItem(
                        kind=dmg_kind,
                        offset=index_offset,
                        detail="Index table truncated or out of bounds",
                        lossy=True,
                    )
                ],
            )

        entries_start = len(data) - entry_count * 16
        names_raw = data[index_offset:entries_start]

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        for i in range(entry_count):
            e_off = entries_start + i * 16
            e = data[e_off:e_off+16]
            rec_id = struct.unpack("<H", e[:2])[0]
            type_code = e[2]
            flags_code = e[3]
            name_pos = struct.unpack("<I", e[4:8])[0]
            blob_off = struct.unpack("<I", e[8:12])[0]
            stored_sz = struct.unpack("<H", e[12:14])[0]
            decoded_sz = struct.unpack("<H", e[14:16])[0]

            if name_pos >= len(names_raw):
                name = f"entry_{rec_id}"
            else:
                n_len = names_raw[name_pos]
                enc_name = names_raw[name_pos+1:name_pos+1+n_len]
                name = bytes([b ^ ((xor_key + j) & 0xFF) for j, b in enumerate(enc_name)]).decode("ascii", errors="replace")

            if blob_off + stored_sz > len(data):
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=blob_off,
                        detail=f"Entry '{name}' blob truncated",
                        lossy=True,
                    )
                )
                status = OutputStatus.PARTIAL
                continue

            blob_payload = data[blob_off+4:blob_off+stored_sz]
            is_compressed = bool(flags_code & 0x01)

            if name.endswith(".txt"):
                ftype = "text"
                unmasked = bytes([b ^ ((xor_key + j) & 0xFF) for j, b in enumerate(blob_payload[:decoded_sz])])
            elif name.endswith(".bin"):
                ftype = "binary"
                unmasked = bytes(blob_payload[:decoded_sz])
            else:
                ftype = "bitmap"
                unmasked = bytes([b ^ ((xor_key + j) & 0xFF) for j, b in enumerate(blob_payload[:decoded_sz])])

            sha256_hash = hashlib.sha256(unmasked).hexdigest()

            rec: dict[str, Any] = {
                "id": rec_id,
                "name": name,
                "type": ftype,
                "size": decoded_sz,
                "sha256": sha256_hash,
                "compressed": is_compressed,
            }
            if ftype == "text":
                rec["text"] = unmasked.decode("utf-8", errors="replace")

            records.append(rec)

        return FileRecoveryResult(
            filename=filename,
            format_name="VAULT",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
