"""Stage 3: Transforms, Checksums, RLE & XOR Algorithms.
Pure, bounds-checked de-obfuscation and decompression routines with zip-bomb guards.
"""

from __future__ import annotations
import zlib
from typing import Optional, Tuple

# ---------------------------------------------------------
# 1. Checksums
# ---------------------------------------------------------

def crc16_ccitt(data: bytes, poly: int = 0x1021, init: int = 0xFFFF) -> int:
    """CRC-16-CCITT (standard poly 0x1021, big-endian/normal)."""
    crc = init
    for b in data:
        crc ^= (b << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

def crc16_arc(data: bytes) -> int:
    """CRC-16-ARC (poly 0x8005 reflected as 0xA001, init 0x0000)."""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc = crc >> 1
    return crc & 0xFFFF

def crc32_ieee(data: bytes) -> int:
    """Standard IEEE 802.3 CRC32."""
    return zlib.crc32(data) & 0xFFFFFFFF

def fletcher16(data: bytes) -> int:
    """Fletcher-16 checksum modulo 255."""
    c0 = 0
    c1 = 0
    for b in data:
        c0 = (c0 + b) % 255
        c1 = (c1 + c0) % 255
    return (c1 << 8) | c0

def xor8_sum(data: bytes) -> int:
    """8-bit XOR checksum."""
    res = 0
    for b in data:
        res ^= b
    return res

def mod256_sum(data: bytes) -> int:
    """8-bit additive sum modulo 256."""
    return sum(data) & 0xFF

def verify_any_checksum(data: bytes, expected: int, width_bits: int = 16) -> Tuple[bool, Optional[str]]:
    """Tests standard algorithms to see if any match expected value."""
    if width_bits == 16:
        if crc16_ccitt(data) == expected:
            return True, "CRC16-CCITT"
        if crc16_arc(data) == expected:
            return True, "CRC16-ARC"
        if fletcher16(data) == expected:
            return True, "Fletcher16"
        if (sum(data) & 0xFFFF) == expected:
            return True, "SUM16"
    elif width_bits == 32:
        if crc32_ieee(data) == expected:
            return True, "CRC32-IEEE"
        if (sum(data) & 0xFFFFFFFF) == expected:
            return True, "SUM32"
    elif width_bits == 8:
        if xor8_sum(data) == expected:
            return True, "XOR8"
        if mod256_sum(data) == expected:
            return True, "MOD256"
    return False, None


# ---------------------------------------------------------
# 2. RLE Decompression with Zip-Bomb Guards
# ---------------------------------------------------------

def rle_decompress_packbits(data: bytes, max_output: int = 1_048_576) -> Tuple[bytes, bool, Optional[str]]:
    """PackBits (Mac/TIFF/Amiga standard) RLE decompression.
    Control byte n (signed/unsigned):
      - 0 <= n <= 127: copy next n + 1 literal bytes
      - 129 <= n <= 255 (or -127 <= n <= -1): repeat next byte (257 - n) times
      - n == 128: NO-OP
    """
    out = bytearray()
    i = 0
    length = len(data)

    while i < length:
        if len(out) >= max_output:
            return bytes(out[:max_output]), False, "MAX_OUTPUT_LIMIT_EXCEEDED"

        n = data[i]
        i += 1

        if n < 128:
            count = n + 1
            if i + count > length:
                # Partial/truncated run
                avail = length - i
                out.extend(data[i:length])
                return bytes(out), False, "TRUNCATED_LITERAL_RUN"
            out.extend(data[i:i + count])
            i += count
        elif n > 128:
            repeat_count = 257 - n
            if i >= length:
                return bytes(out), False, "TRUNCATED_REPEAT_BYTE"
            val = data[i]
            i += 1
            # Zip-bomb protection check
            if len(out) + repeat_count > max_output:
                allowed = max_output - len(out)
                out.extend(bytes([val]) * allowed)
                return bytes(out), False, "MAX_OUTPUT_LIMIT_EXCEEDED"
            out.extend(bytes([val]) * repeat_count)
        else:
            # n == 128 is NOOP
            pass

    return bytes(out), True, None

def rle_decompress_marker(data: bytes, marker: int = 0xFF, max_output: int = 1_048_576) -> Tuple[bytes, bool, Optional[str]]:
    """Marker-based RLE: when b == marker, read count and val."""
    out = bytearray()
    i = 0
    length = len(data)

    while i < length:
        if len(out) >= max_output:
            return bytes(out[:max_output]), False, "MAX_OUTPUT_LIMIT_EXCEEDED"

        b = data[i]
        i += 1

        if b == marker:
            if i >= length:
                out.append(marker)
                return bytes(out), False, "TRUNCATED_MARKER"
            count = data[i]
            i += 1
            if count == 0:
                out.append(marker)
            else:
                if i >= length:
                    return bytes(out), False, "TRUNCATED_REPEAT_VALUE"
                val = data[i]
                i += 1
                if len(out) + count > max_output:
                    allowed = max_output - len(out)
                    out.extend(bytes([val]) * allowed)
                    return bytes(out), False, "MAX_OUTPUT_LIMIT_EXCEEDED"
                out.extend(bytes([val]) * count)
        else:
            out.append(b)

    return bytes(out), True, None


# ---------------------------------------------------------
# 3. XOR Obfuscation & Key Cracker
# ---------------------------------------------------------

def xor_apply(data: bytes, key: bytes | int) -> bytes:
    """Applies XOR key cyclically to data."""
    if isinstance(key, int):
        k = bytes([key & 0xFF])
    else:
        k = bytes(key) if key else b"\x00"
    if not k or k == b"\x00":
        return data

    k_len = len(k)
    return bytes(b ^ k[i % k_len] for i, b in enumerate(data))

def xor_crack_ascii(data: bytes, candidate_key_lens: Tuple[int, ...] = (1, 2, 4)) -> Tuple[bytes, bytes, float]:
    """Recovers the most likely XOR key by scoring printable ASCII and character frequencies."""
    if not data:
        return data, b"\x00", 0.0

    common_english = b"etaoinshrdlu ETAOINSHRDLU"

    def score_slice(slice_bytes: bytes, cand_key: int) -> float:
        score = 0
        for b in slice_bytes:
            dec_b = b ^ cand_key
            if dec_b in common_english:
                score += 3
            elif 32 <= dec_b <= 126 or dec_b in (9, 10, 13):
                score += 1
            elif dec_b == 0:
                score += 0
            else:
                score -= 4
        return score / float(len(slice_bytes))

    best_key = b"\x00"
    best_score = -999999.0
    best_decrypted = data

    for k_len in candidate_key_lens:
        if k_len == 1:
            for cand in range(256):
                sc = score_slice(data, cand)
                if sc > best_score:
                    best_score = sc
                    best_key = bytes([cand])
                    best_decrypted = xor_apply(data, best_key)
        elif k_len in (2, 4) and len(data) >= k_len * 4:
            key_bytes = []
            for col in range(k_len):
                col_data = data[col::k_len]
                col_best_cand = 0
                col_best_score = -999999.0
                for cand in range(256):
                    sc = score_slice(col_data, cand)
                    if sc > col_best_score:
                        col_best_score = sc
                        col_best_cand = cand
                key_bytes.append(col_best_cand)

            key = bytes(key_bytes)
            # overall score
            sc = sum(score_slice(data[c::k_len], key_bytes[c]) for c in range(k_len)) / k_len
            # Apply slight penalty for longer keys to prevent overfitting random noise (Occam's razor)
            margin_required = 0.05 * (k_len - 1)
            if sc > best_score + margin_required:
                best_score = sc
                best_key = key
                best_decrypted = xor_apply(data, best_key)

    norm_score = max(0.0, min(1.0, (best_score + 4.0) / 7.0))
    return best_decrypted, best_key, norm_score


# ---------------------------------------------------------
# 4. Legacy Date/Time Decoders
# ---------------------------------------------------------

def decode_dos_date(val: int) -> Optional[str]:
    """MS-DOS date format: bits 0-4 = day (1-31), 5-8 = month (1-12), 9-15 = year + 1980."""
    day = val & 0x1F
    month = (val >> 5) & 0x0F
    year = ((val >> 9) & 0x7F) + 1980
    if 1 <= month <= 12 and 1 <= day <= 31 and 1980 <= year <= 2099:
        return f"{year:04d}-{month:02d}-{day:02d}"
    return None

def decode_dos_datetime(date_u16: int, time_u16: int) -> Optional[str]:
    """MS-DOS Date & Time decode."""
    d = decode_dos_date(date_u16)
    if not d:
        return None
    hour = (time_u16 >> 11) & 0x1F
    minute = (time_u16 >> 5) & 0x3F
    second = min(59, (time_u16 & 0x1F) * 2)
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        return f"{d}T{hour:02d}:{minute:02d}:{second:02d}"
    return f"{d}T00:00:00"

def decode_epoch(sec: int, epoch_year: int = 1970) -> Optional[str]:
    """Unix timestamp decode with bounds validation between 1970 and 2038."""
    from datetime import datetime, timezone
    try:
        if 0 <= sec <= 2_147_483_647:
            dt = datetime.fromtimestamp(sec, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except Exception:
        pass
    return None
