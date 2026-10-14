"""Core data models representing recovered binary records, damage blocks, and reports."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class RecordStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    CORRUPTED = "corrupted"
    UNRECOVERABLE = "unrecoverable"

class DamageType(str, Enum):
    TRUNCATION = "truncation"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    INVALID_HEADER = "invalid_header"
    CORRUPT_RECORD = "corrupt_record"
    MALFORMED_OFFSET = "malformed_offset"
    UNKNOWN_SIGNATURE = "unknown_signature"
    DECOMPRESSION_ERROR = "decompression_error"

@dataclass
class DamageBlock:
    offset: int
    length: int
    damage_type: DamageType
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "type": self.damage_type.value,
            "description": self.description,
        }

@dataclass
class RecoveredRecord:
    record_id: Any
    status: RecordStatus
    byte_range: tuple[int, int]
    fields: dict[str, Any]
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "id": self.record_id,
            "status": self.status.value,
            "byte_range": list(self.byte_range),
            "data": self.fields,
        }
        if self.errors:
            res["errors"] = self.errors
        return res

@dataclass
class FileRecoveryResult:
    filename: str
    format_name: str
    file_size: int
    is_valid_header: bool
    total_records: int
    recovered_records: list[RecoveredRecord] = field(default_factory=list)
    damages: list[DamageBlock] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.filename,
            "format": self.format_name,
            "file_size": self.file_size,
            "is_valid_header": self.is_valid_header,
            "total_records_recovered": len(self.recovered_records),
            "total_declared_records": self.total_records,
            "records": [r.to_dict() for r in self.recovered_records],
            "damages": [d.to_dict() for d in self.damages],
            "metadata": self.metadata,
        }
