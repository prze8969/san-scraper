"""Stage 5: librevenge Universal Event Bus.
Normalizes decoded records across documents, spreadsheets, and archives.
"""

from __future__ import annotations
from typing import Any, Callable, Dict, List

class DocumentHandler:
    def handle_paragraph(self, index: int, text: str) -> None:
        pass

class SpreadsheetHandler:
    def handle_cell(self, cell: str, row: int, col: int, cell_type: str, value: Any, **kwargs) -> None:
        pass

class ArchiveHandler:
    def handle_entry(self, entry_id: Any, name: str, entry_type: str, size: int, sha256: str, **kwargs) -> None:
        pass

class LibrevengeBus:
    """Universal event dispatcher normalizing structured format outputs."""

    def __init__(self):
        self.doc_handlers: List[DocumentHandler] = []
        self.sheet_handlers: List[SpreadsheetHandler] = []
        self.archive_handlers: List[ArchiveHandler] = []

    def register_document_handler(self, handler: DocumentHandler) -> None:
        self.doc_handlers.append(handler)

    def register_spreadsheet_handler(self, handler: SpreadsheetHandler) -> None:
        self.sheet_handlers.append(handler)

    def register_archive_handler(self, handler: ArchiveHandler) -> None:
        self.archive_handlers.append(handler)

    def dispatch_paragraph(self, index: int, text: str) -> None:
        for h in self.doc_handlers:
            h.handle_paragraph(index, text)

    def dispatch_cell(self, cell: str, row: int, col: int, cell_type: str, value: Any, **kwargs) -> None:
        for h in self.sheet_handlers:
            h.handle_cell(cell, row, col, cell_type, value, **kwargs)

    def dispatch_entry(self, entry_id: Any, name: str, entry_type: str, size: int, sha256: str, **kwargs) -> None:
        for h in self.archive_handlers:
            h.handle_entry(entry_id, name, entry_type, size, sha256, **kwargs)
