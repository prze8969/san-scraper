"""Generic binary file analysis module.

Provides statistical analysis, entropy profiling, string extraction,
signature scanning across the whole buffer, structure heuristics, and damage indicators.
All operations are strictly bounded in runtime, memory, and scan depth.
"""

from __future__ import annotations
import math
import re
import struct
import hashlib
from typing import Any

# Supported and common container signatures
# (name, signature_bytes, description)
SIGNATURE_DATABASE: list[tuple[str, bytes, str]] = [
    # Supported formats
    ("LIBRA-98", b"LIBRA98\x00", "LIBRA-98 legacy database"),
    ("LABLOG", b"LABLOG\x01\x00", "Laboratory Log journal"),
    ("VAULT", b"VAULT\x01\x00\x00", "VAULT archive storage"),
    ("PAK", b"PACK", "id Software Quake PAK archive"),
    ("WKS", b"\x00\x00\x02\x00", "Lotus 1-2-3 BOF record"),
    ("WAD", b"IWAD", "Doom Internal WAD"),
    ("WAD", b"PWAD", "Doom Patch WAD"),
    # Common containers / formats requested
    ("ZIP", b"PK\x03\x04", "ZIP / PKZip archive"),
    ("ZIP", b"PK\x05\x06", "ZIP End of Central Directory"),
    ("PNG", b"\x89PNG\r\n\x1a\n", "Portable Network Graphics"),
    ("GIF", b"GIF87a", "GIF 87a image"),
    ("GIF", b"GIF89a", "GIF 89a image"),
    ("JPEG", b"\xff\xd8\xff", "JPEG image"),
    ("PDF", b"%PDF-", "Adobe Portable Document Format"),
    ("GZIP", b"\x1f\x8b\x08", "GZIP compressed data"),
    ("SQLite", b"SQLite format 3\x00", "SQLite 3 database"),
    ("RIFF", b"RIFF", "Resource Interchange File Format (WAV/AVI)"),
    ("OLE2/CFB", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Microsoft Compound File Binary"),
    ("7z", b"7z\xbc\xaf\x27\x1c", "7-Zip compressed archive"),
    ("RAR", b"Rar!\x1a\x07\x00", "RAR archive v1.5-4.x"),
    ("RAR", b"Rar!\x1a\x07\x01\x00", "RAR archive v5.0+"),
]

# Limits
MAX_SCAN_BYTES = 32 * 1024 * 1024  # 32 MB cap
MAX_STRINGS_EXTRACTED = 250
MIN_STRING_LEN = 4
ENTROPY_BLOCK_SIZE = 256
MAX_SIGNATURE_MATCHES = 100

class FileAnalyzer:
    """Performs bounded generic analysis on any arbitrary binary stream."""

    def __init__(self, data: bytes, filename: str = "") -> None:
        self.filename = filename
        self.raw_data = data
        self.total_size = len(data)
        # Cap scanned buffer for performance and safety bounds
        self.scan_size = min(self.total_size, MAX_SCAN_BYTES)
        self.data = data[:self.scan_size]

    def analyze(self) -> dict[str, Any]:
        """Runs all bounded analysis steps and returns the structured dictionary."""
        sha256_hash = hashlib.sha256(self.raw_data).hexdigest()
        ext_hint = self._get_extension_hint()

        signatures = self._scan_signatures()
        entropy_data = self._calculate_entropy()
        extracted_strings = self._extract_strings()
        heuristics = self._evaluate_heuristics()
        damages = self._detect_damage_indicators(heuristics, signatures)

        return {
            "size": self.total_size,
            "sha256": sha256_hash,
            "extension_hint": ext_hint,
            "signatures": signatures,
            "entropy": entropy_data,
            "strings": extracted_strings,
            "heuristics": heuristics,
            "damage_indicators": damages,
        }

    def _get_extension_hint(self) -> str | None:
        if not self.filename or "." not in self.filename:
            return None
        ext = self.filename.rsplit(".", 1)[-1].lower()
        return ext if ext else None

    def _scan_signatures(self) -> list[dict[str, Any]]:
        """Search the whole file for known magic signatures with offset and confidence."""
        matches: list[dict[str, Any]] = []
        if self.scan_size == 0:
            return matches

        for fmt, sig, desc in SIGNATURE_DATABASE:
            sig_len = len(sig)
            start = 0
            while len(matches) < MAX_SIGNATURE_MATCHES:
                idx = self.data.find(sig, start)
                if idx == -1:
                    break
                # Confidence: 1.0 if at offset 0, 0.85 if inside file
                confidence = 1.0 if idx == 0 else 0.85
                matches.append({
                    "format": fmt,
                    "offset": idx,
                    "length": sig_len,
                    "confidence": confidence,
                    "description": desc,
                })
                start = idx + 1

        matches.sort(key=lambda m: (m["offset"], -m["confidence"]))
        return matches

    def _calculate_entropy(self) -> dict[str, Any]:
        """Computes overall Shannon entropy and per-block entropy profile."""
        if self.scan_size == 0:
            return {
                "overall": 0.0,
                "block_size": ENTROPY_BLOCK_SIZE,
                "block_count": 0,
                "blocks": [],
                "regions": [],
            }

        overall_entropy = self._shannon_entropy(self.data)
        num_blocks = (self.scan_size + ENTROPY_BLOCK_SIZE - 1) // ENTROPY_BLOCK_SIZE
        block_entropies: list[float] = []
        regions: list[dict[str, Any]] = []

        # Analyze each block and classify
        for i in range(num_blocks):
            start = i * ENTROPY_BLOCK_SIZE
            end = min(self.scan_size, start + ENTROPY_BLOCK_SIZE)
            chunk = self.data[start:end]
            ent = self._shannon_entropy(chunk)
            block_entropies.append(round(ent, 3))

            # Classify region
            tag = "mixed"
            if ent > 7.2:
                tag = "high_entropy_compressed_or_encrypted"
            elif ent < 0.5:
                tag = "low_entropy_constant_or_zero"
            elif all(32 <= b <= 126 or b in (9, 10, 13) for b in chunk):
                tag = "text_like"

            if not regions or regions[-1]["type"] != tag:
                regions.append({
                    "start": start,
                    "end": end,
                    "type": tag,
                    "avg_entropy": round(ent, 3),
                })
            else:
                regions[-1]["end"] = end

        return {
            "overall": round(overall_entropy, 3),
            "block_size": ENTROPY_BLOCK_SIZE,
            "block_count": num_blocks,
            "blocks": block_entropies[:128],  # bound stored blocks to avoid huge JSON
            "regions": regions,
        }

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts: dict[int, int] = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _extract_strings(self) -> list[dict[str, Any]]:
        """Extract printable ASCII and UTF-16LE strings (min length 4) with offsets, capped in count."""
        results: list[dict[str, Any]] = []
        if self.scan_size == 0:
            return results

        # Printable ASCII: 0x20-0x7e plus tabs/newlines
        ascii_pattern = re.compile(b"[ -~\\t\\r\\n]{4,}")
        for m in ascii_pattern.finditer(self.data):
            if len(results) >= MAX_STRINGS_EXTRACTED:
                break
            matched_bytes = m.group()
            offset = m.start()
            s = matched_bytes.decode("ascii", errors="replace").strip()
            if len(s) >= MIN_STRING_LEN:
                results.append({
                    "offset": offset,
                    "length": len(matched_bytes),
                    "encoding": "ascii",
                    "string": s[:200],  # bound individual string length
                })

        # UTF-16LE: printable characters alternating with 0x00
        utf16_pattern = re.compile(b"(?:[ -~\\t\\r\\n]\\x00){4,}")
        for m in utf16_pattern.finditer(self.data):
            if len(results) >= MAX_STRINGS_EXTRACTED:
                break
            matched_bytes = m.group()
            offset = m.start()
            try:
                s = matched_bytes.decode("utf-16le", errors="replace").strip()
                if len(s) >= MIN_STRING_LEN:
                    results.append({
                        "offset": offset,
                        "length": len(matched_bytes),
                        "encoding": "utf-16le",
                        "string": s[:200],
                    })
            except Exception:
                pass

        results.sort(key=lambda x: x["offset"])
        return results[:MAX_STRINGS_EXTRACTED]

    def _evaluate_heuristics(self) -> list[dict[str, Any]]:
        """Structure heuristics: stride, length-prefixed, repeated markers, numbers, timestamps, size checks."""
        heuristics: list[dict[str, Any]] = []
        if self.scan_size < 8:
            return heuristics

        # 1. Fixed-width record stride detection (autocorrelation / repeated patterns)
        stride_info = self._detect_stride()
        if stride_info:
            heuristics.append(stride_info)

        # 2. Length-prefixed field detection
        len_prefixed = self._detect_length_prefixed()
        if len_prefixed:
            heuristics.append(len_prefixed)

        # 3. Repeated marker / sync token detection
        sync_markers = self._detect_repeated_markers()
        if sync_markers:
            heuristics.append(sync_markers)

        # 4. Candidate numeric fields and plausible timestamps
        numeric_and_time = self._detect_candidate_numeric_and_timestamps()
        heuristics.extend(numeric_and_time)

        # 5. Header-declared sizes / counts vs actual file size
        size_checks = self._detect_header_declared_sizes()
        if size_checks:
            heuristics.append(size_checks)

        return heuristics

    def _detect_stride(self) -> dict[str, Any] | None:
        """Autocorrelation check over candidate strides from 16 to 256 bytes."""
        if self.scan_size < 64:
            return None

        best_stride = None
        best_score = 0.0

        for stride in [16, 24, 32, 48, 64, 80, 96, 128, 256]:
            if stride * 3 > self.scan_size:
                continue
            # Measure similarity between consecutive blocks
            num_blocks = min(10, self.scan_size // stride)
            if num_blocks < 3:
                continue

            matches = 0
            total_checks = 0
            for i in range(num_blocks - 1):
                b1 = self.data[i * stride : (i + 1) * stride]
                b2 = self.data[(i + 1) * stride : (i + 2) * stride]
                # Compare byte positions (e.g. constant fields, record separators, type tags)
                for j in range(stride):
                    if b1[j] == b2[j]:
                        matches += 1
                    total_checks += 1

            ratio = matches / total_checks if total_checks > 0 else 0
            if ratio > 0.4 and ratio > best_score:
                best_score = ratio
                best_stride = stride

        if best_stride and best_score > 0.45:
            confidence = round(min(0.9, best_score), 2)
            return {
                "heuristic": "fixed_width_record_stride",
                "status": "HYPOTHESIZED",
                "confidence": confidence,
                "evidence": f"Record stride of {best_stride} bytes with {int(best_score*100)}% structural pattern alignment across consecutive blocks",
                "details": {
                    "stride_bytes": best_stride,
                    "estimated_record_count": self.scan_size // best_stride,
                },
            }
        return None

    def _detect_length_prefixed(self) -> dict[str, Any] | None:
        """Looks for sequential length-prefixed chunks (e.g. u16/u32 len followed by len bytes)."""
        if self.scan_size < 16:
            return None

        for offset in [0, 4, 8, 16, 32]:
            if offset + 8 > self.scan_size:
                break
            # Try 2-byte little endian lengths
            pos = offset
            chains = 0
            while pos + 2 < min(self.scan_size, offset + 1024):
                val = struct.unpack_from("<H", self.data, pos)[0]
                if 2 <= val <= 256 and pos + 2 + val <= self.scan_size:
                    chains += 1
                    pos += 2 + val
                else:
                    break
            if chains >= 4:
                return {
                    "heuristic": "length_prefixed_fields",
                    "status": "HYPOTHESIZED",
                    "confidence": round(min(0.85, 0.4 + chains * 0.1), 2),
                    "evidence": f"Found sequence of {chains} length-prefixed blocks (uint16 LE) starting at offset {offset}",
                    "details": {"start_offset": offset, "chain_count": chains},
                }

            # Try 4-byte little endian lengths
            pos = offset
            chains = 0
            while pos + 4 < min(self.scan_size, offset + 2048):
                val = struct.unpack_from("<I", self.data, pos)[0]
                if 4 <= val <= 512 and pos + 4 + val <= self.scan_size:
                    chains += 1
                    pos += 4 + val
                else:
                    break
            if chains >= 3:
                return {
                    "heuristic": "length_prefixed_fields",
                    "status": "HYPOTHESIZED",
                    "confidence": round(min(0.85, 0.4 + chains * 0.15), 2),
                    "evidence": f"Found sequence of {chains} length-prefixed blocks (uint32 LE) starting at offset {offset}",
                    "details": {"start_offset": offset, "chain_count": chains},
                }
        return None

    def _detect_repeated_markers(self) -> dict[str, Any] | None:
        """Looks for recurring 4-byte printable or sync markers (e.g., BLOK, SYNC, RECD, etc.)."""
        if self.scan_size < 32:
            return None

        # Look for 4-byte printable ASCII patterns that appear >= 3 times at intervals > 16 bytes
        marker_counts: dict[bytes, list[int]] = {}
        for i in range(0, self.scan_size - 4, 4):
            tag = self.data[i : i + 4]
            if all(65 <= b <= 90 or 48 <= b <= 57 for b in tag):  # A-Z, 0-9
                marker_counts.setdefault(tag, []).append(i)

        for tag, offsets in marker_counts.items():
            if len(offsets) >= 3:
                # Check consistency of intervals
                diffs = [offsets[j+1] - offsets[j] for j in range(len(offsets) - 1)]
                avg_diff = sum(diffs) // len(diffs)
                return {
                    "heuristic": "repeated_sync_marker",
                    "status": "HYPOTHESIZED",
                    "confidence": 0.75,
                    "evidence": f"Repeated sync token {tag.decode('latin-1')} found {len(offsets)} times (avg interval {avg_diff} bytes)",
                    "details": {
                        "marker": tag.decode("latin-1"),
                        "count": len(offsets),
                        "first_offsets": offsets[:8],
                    },
                }
        return None

    def _detect_candidate_numeric_and_timestamps(self) -> list[dict[str, Any]]:
        """Identifies plausible integers and timestamps (Unix epoch, DOS date/time, FILETIME)."""
        findings: list[dict[str, Any]] = []
        if self.scan_size < 8:
            return findings

        # Check offsets 0 to 64 for plausible timestamps
        max_check = min(64, self.scan_size - 4)
        found_unix = 0
        found_filetime = 0

        # Plausible Unix epoch: 1995 (0x2F73E600) to 2030 (0x70E45800) -> 800,000,000 to 1,900,000,000
        for off in range(0, max_check, 4):
            val_le = struct.unpack_from("<I", self.data, off)[0]
            if 800_000_000 <= val_le <= 1_900_000_000:
                found_unix += 1
                findings.append({
                    "heuristic": "candidate_timestamp_unix",
                    "status": "HYPOTHESIZED",
                    "confidence": 0.65,
                    "evidence": f"Plausible 32-bit Unix timestamp {val_le} at offset {off}",
                    "details": {"offset": off, "value": val_le, "endian": "little"},
                })
                if found_unix >= 3:
                    break

        # Plausible Windows FILETIME (64-bit int: 100-ns intervals since 1601):
        # 1995 to 2030 corresponds to 124,000,000,000,000,000 to 135,000,000,000,000,000
        for off in range(0, min(64, self.scan_size - 8), 8):
            val_le64 = struct.unpack_from("<Q", self.data, off)[0]
            if 124_000_000_000_000_000 <= val_le64 <= 135_000_000_000_000_000:
                found_filetime += 1
                findings.append({
                    "heuristic": "candidate_timestamp_filetime",
                    "status": "HYPOTHESIZED",
                    "confidence": 0.70,
                    "evidence": f"Plausible 64-bit Windows FILETIME timestamp at offset {off}",
                    "details": {"offset": off, "value": val_le64, "endian": "little"},
                })
                if found_filetime >= 2:
                    break

        return findings

    def _detect_header_declared_sizes(self) -> dict[str, Any] | None:
        """Inspects first 64 bytes for fields matching or exceeding actual file size."""
        if self.scan_size < 16:
            return None

        for off in range(0, min(64, self.scan_size - 4), 4):
            val = struct.unpack_from("<I", self.data, off)[0]
            # If value equals file size, or is greater than file size
            if val == self.total_size and val > 64:
                return {
                    "heuristic": "declared_file_size_match",
                    "status": "HYPOTHESIZED",
                    "confidence": 0.85,
                    "evidence": f"Exact file size {val} declared at header offset {off}",
                    "details": {"offset": off, "declared_size": val, "actual_size": self.total_size},
                }
            elif val > self.total_size and val < self.total_size * 10:
                return {
                    "heuristic": "declared_size_exceeds_actual",
                    "status": "HYPOTHESIZED",
                    "confidence": 0.80,
                    "evidence": f"Declared size {val} at offset {off} exceeds actual file size {self.total_size} (likely truncation)",
                    "details": {"offset": off, "declared_size": val, "actual_size": self.total_size},
                }
        return None

    def _detect_damage_indicators(
        self,
        heuristics: list[dict[str, Any]],
        signatures: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Identifies truncation, zero-filled gaps, trailing garbage, and length mismatches."""
        damages: list[dict[str, Any]] = []

        # 1. Truncation from declared size mismatch
        for h in heuristics:
            if h.get("heuristic") == "declared_size_exceeds_actual":
                details = h.get("details", {})
                damages.append({
                    "type": "truncation",
                    "offset": details.get("offset", 0),
                    "description": f"Declared size {details.get('declared_size')} exceeds actual size {details.get('actual_size')}",
                })

        # 2. Large zero-filled gaps
        zero_pattern = re.compile(b"\\x00{64,}")
        for m in zero_pattern.finditer(self.data):
            damages.append({
                "type": "zero_filled_gap",
                "offset": m.start(),
                "length": len(m.group()),
                "description": f"Zero-filled gap of {len(m.group())} bytes detected",
            })
            if len(damages) >= 20:
                break

        # 3. Trailing garbage: high entropy trailing region after standard container or zeros
        if self.total_size > 512 and self.data[-128:] != b"\x00" * 128:
            trailing_entropy = self._shannon_entropy(self.data[-256:])
            if trailing_entropy > 7.5 and any(s["offset"] == 0 for s in signatures):
                damages.append({
                    "type": "trailing_garbage",
                    "offset": max(0, self.total_size - 256),
                    "length": min(256, self.total_size),
                    "description": f"High-entropy trailing data ({trailing_entropy:.2f} bits/byte) after container header",
                })

        return damages
