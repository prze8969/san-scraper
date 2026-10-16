"""Core data models representing recovered binary records, damage blocks, and reports.
Strictly conforms to OUTPUT-CONTRACT.md while also providing the universal IR classes
(DamageEvent, SalvagedRecord, FileRecoveryResult) required by the autonomous engine.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

class OutputStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    UNRECOGNIZED = "unrecognized"
    FAILED = "failed"

class DamageKind(str, Enum):
    TRUNCATED = "truncated"
    CRC_MISMATCH = "crc_mismatch"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    BAD_LENGTH = "bad_length"
    UNPARSED_BYTES = "unparsed_bytes"
    COUNT_MISMATCH = "count_mismatch"
    INVALID_VALUE = "invalid_value"
    OOB_POINTER = "oob_pointer"
    INDEX_MISSING = "index_missing"
    HEADER_CHECKSUM = "header_checksum"
    ENCRYPTED = "encrypted"
    UNKNOWN_RECORD = "unknown_record"
    # Legacy aliases
    TRUNCATION = "truncated"
    INVALID_HEADER = "header_checksum"
    CORRUPT_RECORD = "crc_mismatch"
    MALFORMED_OFFSET = "oob_pointer"
    UNKNOWN_SIGNATURE = "unknown_record"
    DECOMPRESSION_ERROR = "bad_length"

@dataclass
class DamageEvent:
    """Damage event for detailed diagnostic tracking and forensics."""
    offset_start: int
    offset_end: int
    severity: str  # "WARNING" | "ERROR" | "TRUNCATION" | "CHECKSUM_MISMATCH" | "OUT_OF_BOUNDS"
    component: str  # e.g., "header", "record[3]", "index_table", "rle_stream"
    message: str
    raw_hex_preview: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset_start": self.offset_start,
            "offset_end": self.offset_end,
            "severity": self.severity,
            "component": self.component,
            "message": self.message,
            "raw_hex_preview": self.raw_hex_preview,
        }

@dataclass
class DamageItem:
    """Conforms to OUTPUT-CONTRACT.md damage items."""
    kind: DamageKind | str
    offset: int
    detail: str = ""
    lossy: bool = True
    length: int = 0
    description: str = ""

    def __post_init__(self) -> None:
        if not self.detail and self.description:
            self.detail = self.description
        elif not self.description and self.detail:
            self.description = self.detail

    @property
    def damage_type(self) -> Any:
        return self.kind

    def to_dict(self) -> dict[str, Any]:
        k = self.kind.value if isinstance(self.kind, (DamageKind, Enum)) else str(self.kind)
        return {
            "kind": k,
            "offset": self.offset,
            "detail": self.detail,
            "lossy": self.lossy,
        }

# Backward compatibility aliases
DamageBlock = DamageItem
DamageType = DamageKind

class RecordStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    CORRUPTED = "corrupted"
    UNRECOVERABLE = "unrecoverable"
    VERIFIED = "VERIFIED"
    SALVAGED_PARTIAL = "SALVAGED_PARTIAL"
    QUARANTINED = "QUARANTINED"

@dataclass
class SalvagedRecord:
    """Universal IR record representation."""
    record_id: Any
    offset: int = 0
    length: int = 0
    status: str = "VERIFIED"  # "VERIFIED" | "SALVAGED_PARTIAL" | "QUARANTINED"
    record_type: str = "RECORD"
    fields: dict[str, Any] = field(default_factory=dict)
    checksum_valid: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        d = dict(self.fields)
        if "id" not in d and self.record_id is not None:
            d["id"] = self.record_id
        return d

@dataclass
class RecoveredRecord:
    record_id: Any
    status: RecordStatus
    byte_range: tuple[int, int]
    fields: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.record_id,
            "status": self.status.value if isinstance(self.status, Enum) else str(self.status),
            "byte_range": list(self.byte_range),
            "data": self.fields,
        }

class RecordDict(dict):
    @property
    def fields(self) -> dict[str, Any]:
        return self

    @property
    def status(self) -> RecordStatus:
        return RecordStatus.COMPLETE

    @property
    def errors(self) -> list[str]:
        return []

    @property
    def record_id(self) -> Any:
        return self.get("id") if "id" in self else self.get("name")

@dataclass
class FileRecoveryResult:
    filename: str
    format_name: str
    status: OutputStatus | str = OutputStatus.OK
    metadata: dict[str, Any] = field(default_factory=dict)
    records: list[Any] = field(default_factory=list)
    damages: list[DamageItem] = field(default_factory=list)
    file_size: int = 0
    is_valid_header: bool = True
    total_records: int = 0
    recovered_records: list[Any] = field(default_factory=list)
    # Stage 1 & 2 IR Extensions:
    detected_format: Optional[str] = None
    confidence: str = "HIGH"  # "HIGH" | "MEDIUM" | "HEURISTIC" | "NONE"
    source_file: Optional[str] = None
    damage_events: list[DamageEvent] = field(default_factory=list)
    unclaimed_byte_ranges: list[tuple[int, int]] = field(default_factory=list)
    coverage_ratio: float = 1.0

    def __post_init__(self) -> None:
        if self.source_file is None:
            self.source_file = self.filename
        if self.detected_format is None:
            self.detected_format = self.format_name

        if not self.records and self.recovered_records:
            self.records = [r.fields if hasattr(r, "fields") else r for r in self.recovered_records]

        # Convert SalvagedRecord objects or dicts into compliant structures
        normalized_records = []
        for r in self.records:
            if isinstance(r, SalvagedRecord):
                normalized_records.append(RecordDict(r.to_dict()))
            elif isinstance(r, dict) and not isinstance(r, RecordDict):
                normalized_records.append(RecordDict(r))
            else:
                normalized_records.append(r)
        self.records = normalized_records

        if not self.recovered_records and self.records:
            self.recovered_records = self.records
        else:
            self.recovered_records = [
                RecordDict(r) if isinstance(r, dict) and not isinstance(r, RecordDict) else r
                for r in self.recovered_records
            ]

        self.is_valid_header = (self.status in (OutputStatus.OK, OutputStatus.PARTIAL, "ok", "partial"))
        self.total_records = len(self.records)

    def to_dict(self) -> dict[str, Any]:
        st = self.status.value if isinstance(self.status, (OutputStatus, Enum)) else str(self.status)
        recs = [r.to_dict() if hasattr(r, "to_dict") and not isinstance(r, dict) else r for r in self.records]
        return {
            "source_file": self.source_file or self.filename,
            "file": self.source_file or self.filename,
            "format": self.detected_format or self.format_name,
            "status": st,
            "metadata": self.metadata,
            "records": recs,
            "damage": [d.to_dict() for d in self.damages],
        }
