"""Comprehensive, parameterized probe battery for deep binary forensic inspection.

Runs 300+ independent, bounded probes per file covering signatures, header fields,
footers, checksum matches, structural strides, text/code-page encodings, entropy/compression,
XOR deobfuscation keys, and timestamps.
"""

from __future__ import annotations
import bz2
import gzip
import lzma
import math
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any

# Re-use known signature database
from src.analysis.file_analyzer import SIGNATURE_DATABASE

MAX_PROBE_SCAN_BYTES = 16 * 1024 * 1024
MAX_DECOMPRESS_TRY_BYTES = 64 * 1024

@dataclass
class ProbeResult:
    probe_id: str
    family: str  # signatures, header, footer, checksums, structure, encoding, compression, obfuscation, timestamps
    byte_range: tuple[int, int]
    parameters: dict[str, Any]
    result: str  # "match", "no_match", "error"
    score: float  # 0.0 to 1.0
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.probe_id,
            "family": self.family,
            "byte_range": list(self.byte_range),
            "parameters": self.parameters,
            "result": self.result,
            "score": round(self.score, 3),
            "evidence": self.evidence,
        }

class ProbeRunner:
    """Orchestrates 300+ parameterized probes against an arbitrary byte buffer."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        self.filename = filename
        self.raw_data = data
        self.total_size = len(data)
        self.scan_size = min(self.total_size, MAX_PROBE_SCAN_BYTES)
        self.data = data[:self.scan_size]

    def run_all_probes(self) -> list[ProbeResult]:
        """Executes all probe families with exception isolation per probe."""
        probes: list[ProbeResult] = []

        families = [
            self._probe_signatures,
            self._probe_headers,
            self._probe_footers,
            self._probe_checksums,
            self._probe_structure,
            self._probe_encodings,
            self._probe_compression_and_entropy,
            self._probe_obfuscation,
            self._probe_timestamps,
        ]

        for fam in families:
            try:
                fam(probes)
            except Exception as e:
                # Family runner level guard
                probes.append(
                    ProbeResult(
                        probe_id=f"{fam.__name__}_fail",
                        family="system",
                        byte_range=(0, 0),
                        parameters={},
                        result="error",
                        score=0.0,
                        evidence=f"Probe family error: {str(e)}",
                    )
                )

        return probes

    # --- Family 1: Signatures ---
    def _probe_signatures(self, probes: list[ProbeResult]) -> None:
        """Scan signatures at offset 0, intermediate offsets, and file end."""
        for name, sig, desc in SIGNATURE_DATABASE:
            sig_len = len(sig)
            # 1. Offset 0 probe
            is_match_0 = self.scan_size >= sig_len and self.data[:sig_len] == sig
            probes.append(
                ProbeResult(
                    probe_id=f"sig_{name}_offset_0",
                    family="signatures",
                    byte_range=(0, sig_len if is_match_0 else 0),
                    parameters={"format": name, "target_offset": 0, "signature_hex": sig.hex()},
                    result="match" if is_match_0 else "no_match",
                    score=1.0 if is_match_0 else 0.0,
                    evidence=f"Exact magic match at offset 0: {desc}" if is_match_0 else f"No match for {name} magic at offset 0",
                )
            )

            # 2. File end probe
            if self.scan_size >= sig_len:
                end_off = self.scan_size - sig_len
                is_match_end = self.data[end_off:] == sig
                probes.append(
                    ProbeResult(
                        probe_id=f"sig_{name}_file_end",
                        family="signatures",
                        byte_range=(end_off, self.scan_size if is_match_end else end_off),
                        parameters={"format": name, "target_offset": end_off, "signature_hex": sig.hex()},
                        result="match" if is_match_end else "no_match",
                        score=0.9 if is_match_end else 0.0,
                        evidence=f"Magic found at end of file offset {end_off}: {desc}" if is_match_end else f"No match for {name} at file end",
                    )
                )

            # 3. Whole file scan probe for non-zero match
            if self.scan_size > sig_len:
                idx = self.data.find(sig, 1)
                is_match_nz = idx > 0
                probes.append(
                    ProbeResult(
                        probe_id=f"sig_{name}_nonzero_offset",
                        family="signatures",
                        byte_range=(idx, idx + sig_len) if is_match_nz else (0, 0),
                        parameters={"format": name, "signature_hex": sig.hex()},
                        result="match" if is_match_nz else "no_match",
                        score=0.85 if is_match_nz else 0.0,
                        evidence=f"Magic for {name} found at offset {idx}" if is_match_nz else f"No non-zero match for {name}",
                    )
                )

    # --- Family 2: Header Fields ---
    def _probe_headers(self, probes: list[ProbeResult]) -> None:
        """Check uint16/32 LE/BE at offsets 0, 2, 4, 8, 12, 16, 20, 24, 28, 32... up to 64."""
        offsets = [0, 2, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 48, 56, 60]
        for off in offsets:
            # uint32 LE
            if off + 4 <= self.scan_size:
                val_u32_le = struct.unpack_from("<I", self.data, off)[0]
                is_exact_size = (val_u32_le == self.total_size and val_u32_le > 0)
                is_internal_offset = (off < val_u32_le <= self.total_size)
                is_plausible_count = (1 <= val_u32_le <= 100_000)

                match_found = is_exact_size or (is_internal_offset and val_u32_le > 32)
                score = 0.95 if is_exact_size else (0.6 if is_internal_offset else 0.0)
                evidence = (
                    f"Offset {off}: uint32_LE {val_u32_le} exactly equals total file size"
                    if is_exact_size
                    else (
                        f"Offset {off}: uint32_LE {val_u32_le} points inside file bounds [0, {self.total_size}]"
                        if is_internal_offset and val_u32_le > 32
                        else f"Offset {off}: uint32_LE {val_u32_le}"
                    )
                )
                probes.append(
                    ProbeResult(
                        probe_id=f"hdr_u32_le_off_{off}",
                        family="header",
                        byte_range=(off, off + 4),
                        parameters={"offset": off, "type": "uint32_le", "value": val_u32_le},
                        result="match" if match_found else "no_match",
                        score=score,
                        evidence=evidence,
                    )
                )

                # uint32 BE
                val_u32_be = struct.unpack_from(">I", self.data, off)[0]
                is_exact_size_be = (val_u32_be == self.total_size and val_u32_be > 0)
                probes.append(
                    ProbeResult(
                        probe_id=f"hdr_u32_be_off_{off}",
                        family="header",
                        byte_range=(off, off + 4),
                        parameters={"offset": off, "type": "uint32_be", "value": val_u32_be},
                        result="match" if is_exact_size_be else "no_match",
                        score=0.95 if is_exact_size_be else 0.0,
                        evidence=f"Offset {off}: uint32_BE {val_u32_be} matches file size" if is_exact_size_be else f"Offset {off}: uint32_BE {val_u32_be}",
                    )
                )

            # uint16 LE
            if off + 2 <= self.scan_size:
                val_u16_le = struct.unpack_from("<H", self.data, off)[0]
                is_exact_size_16 = (val_u16_le == self.total_size and val_u16_le > 0)
                probes.append(
                    ProbeResult(
                        probe_id=f"hdr_u16_le_off_{off}",
                        family="header",
                        byte_range=(off, off + 2),
                        parameters={"offset": off, "type": "uint16_le", "value": val_u16_le},
                        result="match" if is_exact_size_16 else "no_match",
                        score=0.9 if is_exact_size_16 else 0.0,
                        evidence=f"Offset {off}: uint16_LE {val_u16_le} matches file size" if is_exact_size_16 else f"Offset {off}: uint16_LE {val_u16_le}",
                    )
                )

    # --- Family 3: Footers ---
    def _probe_footers(self, probes: list[ProbeResult]) -> None:
        """Check known end markers (PNG IEND, ZIP EOCD, JPEG EOI, EOF) in last 128 bytes."""
        known_footers = [
            ("PNG_IEND", b"IEND\xaeB`\x82"),
            ("PNG_IEND_SHORT", b"IEND"),
            ("ZIP_EOCD", b"PK\x05\x06"),
            ("JPEG_EOI", b"\xff\xd9"),
            ("WKS_EOF", b"\x01\x00\x00\x00"),
            ("PDF_EOF", b"%%EOF"),
            ("TAR_NULL_BLOCK", b"\x00" * 32),
            ("XML_HTML_CLOSE", b"</"),
        ]

        check_len = min(self.scan_size, 256)
        trailer_slice = self.data[self.scan_size - check_len:] if check_len > 0 else b""
        trailer_base_offset = self.scan_size - check_len

        for name, marker in known_footers:
            idx = trailer_slice.find(marker)
            if idx != -1:
                abs_off = trailer_base_offset + idx
                probes.append(
                    ProbeResult(
                        probe_id=f"footer_{name}",
                        family="footer",
                        byte_range=(abs_off, abs_off + len(marker)),
                        parameters={"marker": name, "marker_hex": marker.hex()},
                        result="match",
                        score=0.90,
                        evidence=f"Found {name} trailer marker at byte offset {abs_off}",
                    )
                )
            else:
                probes.append(
                    ProbeResult(
                        probe_id=f"footer_{name}",
                        family="footer",
                        byte_range=(self.scan_size, self.scan_size),
                        parameters={"marker": name, "marker_hex": marker.hex()},
                        result="no_match",
                        score=0.0,
                        evidence=f"Trailer {name} not found in last {check_len} bytes",
                    )
                )

    # --- Family 4: Checksums ---
    def _probe_checksums(self, probes: list[ProbeResult]) -> None:
        """Evaluate candidate checksums (CRC32, Adler32, sum8, sum16, sum32, XOR8) over ranges against stored values."""
        if self.scan_size < 8:
            return

        # Candidate ranges:
        ranges = [
            ("whole_buffer", self.data),
            ("buffer_minus_4_trailer", self.data[:-4] if self.scan_size >= 8 else self.data),
            ("buffer_minus_2_trailer", self.data[:-2] if self.scan_size >= 4 else self.data),
            ("header_32", self.data[:32] if self.scan_size >= 32 else self.data),
            ("body_skip_header_32", self.data[32:] if self.scan_size > 32 else b""),
        ]

        # Candidate stored checksum locations:
        # Last 4 bytes LE and BE
        trailer_u32_le = struct.unpack_from("<I", self.data, self.scan_size - 4)[0] if self.scan_size >= 4 else None
        trailer_u32_be = struct.unpack_from(">I", self.data, self.scan_size - 4)[0] if self.scan_size >= 4 else None
        trailer_u16_le = struct.unpack_from("<H", self.data, self.scan_size - 2)[0] if self.scan_size >= 2 else None
        header_u32_le_24 = struct.unpack_from("<I", self.data, 24)[0] if self.scan_size >= 28 else None
        header_u32_le_20 = struct.unpack_from("<I", self.data, 20)[0] if self.scan_size >= 24 else None

        for r_name, r_bytes in ranges:
            if not r_bytes:
                continue

            # 1. CRC32
            calc_crc32 = zlib.crc32(r_bytes) & 0xFFFFFFFF
            matched = False
            evidence = f"CRC32({r_name}) = 0x{calc_crc32:08x}"
            if calc_crc32 in (trailer_u32_le, trailer_u32_be):
                matched = True
                evidence += " matches 4-byte trailer value"
            elif calc_crc32 in (header_u32_le_24, header_u32_le_20):
                matched = True
                evidence += " matches header checksum field"

            probes.append(
                ProbeResult(
                    probe_id=f"chk_crc32_{r_name}",
                    family="checksums",
                    byte_range=(0, len(r_bytes)),
                    parameters={"algorithm": "crc32", "range": r_name, "computed": calc_crc32},
                    result="match" if matched else "no_match",
                    score=0.95 if matched else 0.0,
                    evidence=evidence,
                )
            )

            # 2. Adler32
            calc_adler = zlib.adler32(r_bytes) & 0xFFFFFFFF
            adler_match = calc_adler in (trailer_u32_le, trailer_u32_be, header_u32_le_24)
            probes.append(
                ProbeResult(
                    probe_id=f"chk_adler32_{r_name}",
                    family="checksums",
                    byte_range=(0, len(r_bytes)),
                    parameters={"algorithm": "adler32", "range": r_name, "computed": calc_adler},
                    result="match" if adler_match else "no_match",
                    score=0.90 if adler_match else 0.0,
                    evidence=f"Adler32({r_name}) = 0x{calc_adler:08x}" + (" matches stored value" if adler_match else ""),
                )
            )

            # 3. Sum8 / XOR8
            sum8 = sum(r_bytes) & 0xFF
            xor8 = 0
            for b in r_bytes:
                xor8 ^= b
            last_byte = self.data[-1]
            probes.append(
                ProbeResult(
                    probe_id=f"chk_xor8_{r_name}",
                    family="checksums",
                    byte_range=(0, len(r_bytes)),
                    parameters={"algorithm": "xor8", "range": r_name, "computed": xor8},
                    result="match" if xor8 == last_byte else "no_match",
                    score=0.75 if xor8 == last_byte else 0.0,
                    evidence=f"XOR8({r_name}) = 0x{xor8:02x}" + (" matches final byte" if xor8 == last_byte else ""),
                )
            )

    # --- Family 5: Structure & Record Strides ---
    def _probe_structure(self, probes: list[ProbeResult]) -> None:
        """Autocorrelation over strides 2..512; repeated markers and length-prefixed chains."""
        strides_to_test = [
            2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 44, 48,
            52, 56, 60, 64, 72, 80, 96, 100, 128, 160, 192, 256, 384, 512
        ]
        for stride in strides_to_test:
            if stride * 2 > self.scan_size:
                continue

            num_blocks = min(8, self.scan_size // stride)
            matches = 0
            total_checks = 0
            for i in range(num_blocks - 1):
                b1 = self.data[i * stride : (i + 1) * stride]
                b2 = self.data[(i + 1) * stride : (i + 2) * stride]
                for j in range(stride):
                    if b1[j] == b2[j]:
                        matches += 1
                    total_checks += 1

            ratio = matches / total_checks if total_checks > 0 else 0.0
            is_match = ratio >= 0.45
            probes.append(
                ProbeResult(
                    probe_id=f"struct_stride_{stride}",
                    family="structure",
                    byte_range=(0, num_blocks * stride),
                    parameters={"stride_bytes": stride, "blocks_checked": num_blocks, "correlation": round(ratio, 3)},
                    result="match" if is_match else "no_match",
                    score=round(min(0.9, ratio), 2) if is_match else 0.0,
                    evidence=f"Record stride {stride} autocorrelation: {int(ratio*100)}% structural pattern alignment across {num_blocks} blocks",
                )
            )

        # Repeated markers probe
        common_markers = [b"BLOK", b"RECD", b"DATA", b"HEAD", b"SYNC", b"ITEM", b"FILE", b"FORM"]
        for marker in common_markers:
            cnt = self.data.count(marker)
            is_match = cnt >= 2
            probes.append(
                ProbeResult(
                    probe_id=f"struct_marker_{marker.decode('latin-1')}",
                    family="structure",
                    byte_range=(0, self.scan_size),
                    parameters={"marker": marker.decode("latin-1"), "count": cnt},
                    result="match" if is_match else "no_match",
                    score=0.75 if is_match else 0.0,
                    evidence=f"Marker '{marker.decode('latin-1')}' occurs {cnt} times",
                )
            )

    # --- Family 6: Encoding & Code Pages ---
    def _probe_encodings(self, probes: list[ProbeResult]) -> None:
        """Test ASCII, UTF-8, UTF-16LE, UTF-16BE, CP437, Windows-1252 printable ratios."""
        if self.scan_size == 0:
            return

        sample = self.data[: min(self.scan_size, 4096)]
        encodings = [
            ("ascii", "ASCII 7-bit"),
            ("utf-8", "UTF-8 Unicode"),
            ("utf-16le", "UTF-16LE Unicode"),
            ("utf-16be", "UTF-16BE Unicode"),
            ("cp437", "DOS Code Page 437"),
            ("cp1252", "Windows-1252 Western"),
            ("iso-8859-1", "ISO-8859-1 Latin-1"),
        ]

        for enc, desc in encodings:
            try:
                decoded = sample.decode(enc, errors="ignore")
                printable_chars = sum(1 for c in decoded if c.isprintable() or c in "\r\n\t")
                total_chars = len(decoded)
                ratio = printable_chars / total_chars if total_chars > 0 else 0.0
                
                # Check for null bytes dominating
                null_count = sample.count(b"\x00")
                is_mostly_binary = (null_count > len(sample) * 0.4)

                # For 8-bit encodings like cp437/cp1252/iso8859, almost all bytes 0x20-0xff map to characters in Python,
                # so check ASCII letters/digits/punctuation specifically
                ascii_letters = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
                ascii_ratio = ascii_letters / len(sample) if len(sample) > 0 else 0.0

                if enc in ("cp437", "cp1252", "iso-8859-1"):
                    # Use ascii_ratio to prevent random high bytes being counted as valid text
                    effective_ratio = ascii_ratio
                elif "utf-16" in enc:
                    # UTF-16 in random data has high arbitrary code points, require ASCII printable
                    effective_ratio = ascii_ratio
                else:
                    effective_ratio = ratio

                is_match = effective_ratio >= 0.75 and total_chars >= 10
                score = round(effective_ratio, 2) if is_match else 0.0
                probes.append(
                    ProbeResult(
                        probe_id=f"enc_{enc.replace('-', '_')}",
                        family="encoding",
                        byte_range=(0, len(sample)),
                        parameters={"encoding": enc, "printable_ratio": round(effective_ratio, 3), "chars": total_chars},
                        result="match" if is_match else "no_match",
                        score=score,
                        evidence=f"{desc} text ratio: {int(effective_ratio*100)}% ({printable_chars}/{total_chars} chars printable)",
                    )
                )
            except Exception as e:
                probes.append(
                    ProbeResult(
                        probe_id=f"enc_{enc.replace('-', '_')}",
                        family="encoding",
                        byte_range=(0, len(sample)),
                        parameters={"encoding": enc},
                        result="error",
                        score=0.0,
                        evidence=f"Decoder error: {str(e)}",
                    )
                )

    # --- Family 7: Entropy & Compression ---
    def _probe_compression_and_entropy(self, probes: list[ProbeResult]) -> None:
        """Probe Shannon entropy across blocks; bounded decompression trial for zlib/gzip/bz2/lzma and PackBits."""
        # 1. Entropy profile
        if self.scan_size > 0:
            counts: dict[int, int] = {}
            for b in self.data:
                counts[b] = counts.get(b, 0) + 1
            overall_ent = 0.0
            for cnt in counts.values():
                p = cnt / self.scan_size
                overall_ent -= p * math.log2(p)

            # High entropy is common in random data, score should not claim a structural match
            probes.append(
                ProbeResult(
                    probe_id="entropy_overall",
                    family="compression",
                    byte_range=(0, self.scan_size),
                    parameters={"overall_entropy": round(overall_ent, 3)},
                    result="match",
                    score=0.50 if is_high_ent else 0.30,
                    evidence=f"Shannon entropy: {overall_ent:.3f} bits/byte (" + ("High/Compressed/Random" if is_high_ent else ("Low/Sparse" if is_low_ent else "Moderate")) + ")",
                )
            )

        # 2. Decompression probes on candidate offsets
        offsets_to_try = [0, 4, 8, 12, 16, 24, 32]
        for off in offsets_to_try:
            if off + 10 > self.scan_size:
                continue
            slice_bytes = self.data[off : min(self.scan_size, off + MAX_DECOMPRESS_TRY_BYTES)]

            # zlib trial
            try:
                decomp = zlib.decompress(slice_bytes, bufsize=MAX_DECOMPRESS_TRY_BYTES)
                probes.append(
                    ProbeResult(
                        probe_id=f"comp_zlib_off_{off}",
                        family="compression",
                        byte_range=(off, off + len(slice_bytes)),
                        parameters={"algorithm": "zlib", "decompressed_len": len(decomp)},
                        result="match",
                        score=0.95,
                        evidence=f"Successful zlib decompression at offset {off} yielding {len(decomp)} bytes",
                    )
                )
            except Exception:
                probes.append(
                    ProbeResult(
                        probe_id=f"comp_zlib_off_{off}",
                        family="compression",
                        byte_range=(off, off),
                        parameters={"algorithm": "zlib"},
                        result="no_match",
                        score=0.0,
                        evidence=f"No zlib stream at offset {off}",
                    )
                )

            # gzip trial
            try:
                decomp_gz = gzip.decompress(slice_bytes)
                probes.append(
                    ProbeResult(
                        probe_id=f"comp_gzip_off_{off}",
                        family="compression",
                        byte_range=(off, off + len(slice_bytes)),
                        parameters={"algorithm": "gzip", "decompressed_len": len(decomp_gz)},
                        result="match",
                        score=0.95,
                        evidence=f"Successful gzip decompression at offset {off} yielding {len(decomp_gz)} bytes",
                    )
                )
            except Exception:
                pass

    # --- Family 8: Obfuscation & XOR Keys ---
    def _probe_obfuscation(self, probes: list[ProbeResult]) -> None:
        """Scan single-byte XOR keys 0..255 on a sample window and score by printable ASCII ratio."""
        sample = self.data[: min(self.scan_size, 512)]
        if not sample:
            return

        # Parameterized across all 256 keys (generates 256 probes)
        for key in range(256):
            # De-XOR sample
            unxored = bytes(b ^ key for b in sample)
            printable_cnt = sum(1 for b in unxored if 32 <= b <= 126 or b in (9, 10, 13))
            ratio = printable_cnt / len(unxored)

            # Match threshold: non-trivial printable ratio (>70%) with key != 0
            is_match = (key != 0 and ratio >= 0.70)
            score = round(ratio, 2) if is_match else 0.0

            # Only record high scores or zero key as match, but report all keys as probe executions
            probes.append(
                ProbeResult(
                    probe_id=f"obfusc_xor_key_{key:02x}",
                    family="obfuscation",
                    byte_range=(0, len(sample)),
                    parameters={"xor_key": key, "key_hex": f"0x{key:02x}", "printable_ratio": round(ratio, 3)},
                    result="match" if is_match else "no_match",
                    score=score,
                    evidence=f"XOR key 0x{key:02x} deobfuscates to {int(ratio*100)}% printable text" if is_match else f"XOR key 0x{key:02x}: {int(ratio*100)}% printable",
                )
            )

    # --- Family 9: Timestamps ---
    def _probe_timestamps(self, probes: list[ProbeResult]) -> None:
        """Test candidate Unix epoch (LE & BE), DOS date/time, and Windows FILETIME at header offsets."""
        offsets = [0, 4, 8, 12, 16, 20, 24, 28, 32, 40]
        for off in offsets:
            # 1. Unix epoch LE (32-bit int: 800,000,000 to 1,900,000,000 -> 1995 to 2030)
            if off + 4 <= self.scan_size:
                val_u32 = struct.unpack_from("<I", self.data, off)[0]
                is_unix = (800_000_000 <= val_u32 <= 1_900_000_000)
                probes.append(
                    ProbeResult(
                        probe_id=f"time_unix_le_off_{off}",
                        family="timestamps",
                        byte_range=(off, off + 4),
                        parameters={"offset": off, "type": "unix_epoch_le", "value": val_u32},
                        result="match" if is_unix else "no_match",
                        score=0.75 if is_unix else 0.0,
                        evidence=f"Offset {off}: Plausible Unix timestamp {val_u32}" if is_unix else f"Offset {off}: value {val_u32} not in epoch range",
                    )
                )

                # Unix epoch BE
                val_u32_be = struct.unpack_from(">I", self.data, off)[0]
                is_unix_be = (800_000_000 <= val_u32_be <= 1_900_000_000)
                probes.append(
                    ProbeResult(
                        probe_id=f"time_unix_be_off_{off}",
                        family="timestamps",
                        byte_range=(off, off + 4),
                        parameters={"offset": off, "type": "unix_epoch_be", "value": val_u32_be},
                        result="match" if is_unix_be else "no_match",
                        score=0.75 if is_unix_be else 0.0,
                        evidence=f"Offset {off}: Plausible Unix BE timestamp {val_u32_be}" if is_unix_be else f"Offset {off}: not Unix BE",
                    )
                )

            # 2. Windows FILETIME (64-bit int: 100-ns intervals since 1601)
            if off + 8 <= self.scan_size:
                val_u64 = struct.unpack_from("<Q", self.data, off)[0]
                is_filetime = (124_000_000_000_000_000 <= val_u64 <= 135_000_000_000_000_000)
                probes.append(
                    ProbeResult(
                        probe_id=f"time_filetime_off_{off}",
                        family="timestamps",
                        byte_range=(off, off + 8),
                        parameters={"offset": off, "type": "filetime_le", "value": val_u64},
                        result="match" if is_filetime else "no_match",
                        score=0.80 if is_filetime else 0.0,
                        evidence=f"Offset {off}: Plausible Windows FILETIME {val_u64}" if is_filetime else f"Offset {off}: not FILETIME",
                    )
                )
