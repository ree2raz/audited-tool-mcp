"""Structured JSONL audit logger — one record per request.

Appends AuditRecord to a JSONL file. Never logs raw PII values —
detections contain categories and offsets; raw text is hashed.
The vault file is separate and access-controlled.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from audited_tool_mcp.models import AuditRecord

logger = logging.getLogger(__name__)


class AuditLogger:
    """Append-only JSONL audit logger.

    Each request through the compliance pipeline produces exactly one
    AuditRecord. Records are appended atomically (one line per write).
    """

    def __init__(self, path: str | None = None):
        self.path = path or os.environ.get("AUDIT_LOG_PATH", "./audit.jsonl")
        # Ensure parent directory exists
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: AuditRecord) -> None:
        """Append a single audit record to the JSONL file.

        The record is serialized to a single line of JSON and appended.
        File writes are atomic at the line level on POSIX systems.
        """
        line = record.model_dump_json()
        with open(self.path, "a") as f:
            f.write(line + "\n")

        logger.debug(
            "Audit record written: request_id=%s, status=%s, tool=%s",
            record.request_id,
            record.status.value,
            record.tool_name,
        )

    def read_all(self) -> list[AuditRecord]:
        """Read all audit records from the log file.

        Primarily for testing and eval harness use.
        """
        records = []
        path = Path(self.path)
        if not path.exists():
            return records

        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(AuditRecord.model_validate_json(line))

        return records

    def clear(self) -> None:
        """Clear the audit log. For testing only."""
        path = Path(self.path)
        if path.exists():
            path.unlink()
