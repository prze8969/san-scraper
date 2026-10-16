"""CVT (Commodore 64 GEOS Convert) format parser conforming to OUTPUT-CONTRACT.md.
Verified against s18.cvt and s19.cvt.
"""

from __future__ import annotations
import struct
from typing import Any
from src.formats.base import BaseParser
from src.reader import BoundedBinaryReader
from src.models import FileRecoveryResult, OutputStatus, DamageItem, DamageKind

def petscii_to_ascii(b_seq: bytes) -> str:
    res: list[str] = []
    for b in b_seq:
        if b == 0 or b == 0xA0:  # padding / null
            continue
        if 0xC1 <= b <= 0xDA:  # uppercase
            res.append(chr(b - 0x80))
        elif 0x41 <= b <= 0x5A:  # lowercase in CBM lower/upper mode
            res.append(chr(b).lower())
        elif 0x61 <= b <= 0x7A:
            res.append(chr(b))
        elif b == 0x0D:
            res.append("\n")
        elif 32 <= b <= 126:
            res.append(chr(b))
    return "".join(res)

class CvtParser(BaseParser):
    def parse(self, filename: str, reader: BoundedBinaryReader) -> FileRecoveryResult:
        data = reader.peek_bytes(reader.size)
        if len(data) < 254:
            return FileRecoveryResult(
                filename=filename,
                format_name="CVT",
                status=OutputStatus.FAILED,
                damages=[
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=0,
                        detail="Header truncated (less than 254 bytes)",
                        lossy=True,
                    )
                ],
            )

        # In GEOS convert: signature at offset 30: b"PRG formatted GEOS file"
        if b"PRG formatted GEOS file" not in data[:64]:
            return FileRecoveryResult(
                filename=filename,
                format_name="CVT",
                status=OutputStatus.UNRECOGNIZED,
                damages=[
                    DamageItem(
                        kind=DamageKind.HEADER_CHECKSUM,
                        offset=0,
                        detail="Missing GEOS Convert signature",
                        lossy=True,
                    )
                ],
            )

        name_raw = data[3:19]
        name = petscii_to_ascii(name_raw)

        struct_code = data[21]
        structure = "vlir" if struct_code == 1 else "seq"
        geos_type = data[22]
        year = 1900 + data[23]
        month = data[24]
        day = data[25]
        hour = data[26]
        minute = data[27]
        modified = f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}"
        declared_blocks = struct.unpack("<H", data[28:30])[0]

        # Info block at offset 254
        class_name = ""
        author = ""
        description = ""
        if len(data) >= 314:
            class_name = petscii_to_ascii(data[254:274])
            author = petscii_to_ascii(data[274:294])
            description = petscii_to_ascii(data[294:314])

        metadata = {
            "name": name,
            "structure": structure,
            "geos_type": geos_type,
            "modified": modified,
            "class_name": class_name,
            "author": author,
            "description": description,
            "declared_blocks": declared_blocks,
        }

        records: list[dict[str, Any]] = []
        damages: list[DamageItem] = []
        status = OutputStatus.OK

        if structure == "seq":
            # Direct sequential data from offset 508
            if len(data) > 508:
                payload = data[508:]
                text = petscii_to_ascii(payload)
                records.append({
                    "slot": 0,
                    "text": text,
                })
            else:
                status = OutputStatus.PARTIAL
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=len(data),
                        detail="No data blocks present",
                        lossy=True,
                    )
                )
        else:
            # VLIR table at 508 (254 bytes)
            if len(data) >= 762:
                vlir_table = data[508:762]
                block_pos = 762
                for slot in range(127):
                    num_blocks = vlir_table[slot*2]
                    last_bytes = vlir_table[slot*2+1]
                    if num_blocks == 0 and last_bytes == 255:
                        continue  # Empty record
                    if num_blocks == 0 and last_bytes == 0:
                        continue  # Empty slot
                    
                    # Read chained blocks for this slot
                    slot_bytes = bytearray()
                    for b_idx in range(num_blocks):
                        if block_pos >= len(data):
                            status = OutputStatus.PARTIAL
                            damages.append(
                                DamageItem(
                                    kind=DamageKind.TRUNCATED,
                                    offset=block_pos,
                                    detail=f"VLIR slot {slot} block {b_idx} truncated",
                                    lossy=True,
                                )
                            )
                            break
                        end_byte = 254 if b_idx < num_blocks - 1 else last_bytes
                        slot_bytes.extend(data[block_pos:block_pos+end_byte])
                        block_pos += 254

                    records.append({
                        "slot": slot,
                        "text": petscii_to_ascii(bytes(slot_bytes)),
                    })
            else:
                status = OutputStatus.PARTIAL
                damages.append(
                    DamageItem(
                        kind=DamageKind.TRUNCATED,
                        offset=508,
                        detail="VLIR table truncated",
                        lossy=True,
                    )
                )

        return FileRecoveryResult(
            filename=filename,
            format_name="CVT",
            status=status,
            metadata=metadata,
            records=records,
            damages=damages,
        )
