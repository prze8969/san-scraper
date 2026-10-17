"""Heuristic fallback analyzer for unknown or undocumented binary formats.
Extracts Shannon entropy, classifies stream type, recovers printable string runs,
and builds heuristic structured records.
"""

from __future__ import annotations
import math
import string
from src.models import SalvagedRecord, DamageEvent

def analyze_unknown_stream(file_bytes: bytes) -> tuple[dict, list[SalvagedRecord], list[DamageEvent]]:
    """
    Performs heuristic analysis on an unknown or undocumented binary file:
    1. Computes Shannon entropy to classify stream type (Text, Structured Binary, Random/Encrypted).
    2. Scans for printable ASCII / UTF-8 string runs (length >= 4).
    3. Emits heuristic SalvagedRecord objects for extracted strings and block chunks.
    """
    if not file_bytes:
        return {"analysis_type": "empty", "entropy": 0.0}, [], []

    # 1. Calculate Shannon Entropy
    entropy = 0.0
    if len(file_bytes) > 0:
        freq: dict[int, int] = {}
        for b in file_bytes:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / len(file_bytes)
            entropy -= p * math.log2(p)

    # Classify stream based on entropy
    if entropy < 3.5:
        stream_type = "low_entropy_text_or_sparse"
    elif entropy < 7.0:
        stream_type = "structured_binary_or_code"
    else:
        stream_type = "high_entropy_encrypted_or_compressed"

    # 2. Extract Printable String Runs (Length >= 4)
    strings_found: list[dict] = []
    current_str: list[str] = []
    current_start = 0

    for i, b in enumerate(file_bytes):
        # Printable ASCII range: 0x20 to 0x7E, plus tab/newline
        if 32 <= b <= 126 or b in (9, 10, 13):
            if not current_str:
                current_start = i
            current_str.append(chr(b))
        else:
            if len(current_str) >= 4:
                text_val = "".join(current_str).strip()
                if text_val:
                    strings_found.append({
                        "offset": current_start,
                        "length": len(current_str),
                        "text": text_val
                    })
            current_str = []

    if len(current_str) >= 4:
        text_val = "".join(current_str).strip()
        if text_val:
            strings_found.append({
                "offset": current_start,
                "length": len(current_str),
                "text": text_val
            })

    # 3. Build Heuristic Salvaged Records
    records: list[SalvagedRecord] = []
    for idx, s in enumerate(strings_found[:50]):  # Cap at first 50 strings
        records.append(SalvagedRecord(
            record_id=idx,
            offset=s["offset"],
            length=s["length"],
            status="SALVAGED_PARTIAL",
            record_type="HEURISTIC_STRING_RUN",
            fields={
                "extracted_string": s["text"],
                "encoding": "ascii"
            },
            checksum_valid=None
        ))

    metadata = {
        "analysis_type": "heuristic_fallback",
        "stream_classification": stream_type,
        "shannon_entropy": round(entropy, 4),
        "total_strings_extracted": len(strings_found)
    }

    damage = [
        DamageEvent(
            offset_start=0,
            offset_end=len(file_bytes),
            severity="WARNING",
            component="router_fallback",
            message=f"File format unrecognized. Applied heuristic analysis (Entropy: {entropy:.2f}, Type: {stream_type})",
            raw_hex_preview=file_bytes[:16].hex()
        )
    ]

    return metadata, records, damage
