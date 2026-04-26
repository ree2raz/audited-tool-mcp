"""SQL query tool — read-only SQL execution against the synthetic FS database.

Executes SELECT queries against the SQLite database, applies column filtering
based on RBAC permissions, and returns results as formatted text.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from audited_tool_mcp.models import Role
from audited_tool_mcp.rbac import filter_columns, _extract_tables

logger = logging.getLogger(__name__)

_DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "synthetic_fs.sqlite"))
_engine: Engine | None = None


def _get_engine() -> Engine:
    """Lazy-create a read-only SQLAlchemy engine."""
    global _engine
    if _engine is None:
        db_path = Path(_DB_PATH)
        if not db_path.exists():
            raise FileNotFoundError(
                f"Database not found at {db_path}. Run 'make seed' or 'python scripts/seed_data.py' first."
            )
        _engine = create_engine(f"sqlite:///{db_path}", echo=False)
    return _engine


def execute_sql(query: str, role: Role | None = None) -> str:
    """Execute a read-only SQL query and return results as canonical JSON.

    Args:
        query: SQL SELECT query to execute
        role: If provided, columns are filtered based on RBAC permissions

    Returns:
        Canonical JSON string with deterministic key ordering for reproducible
        PII scanning.

    Raises:
        ValueError: If the query is not a SELECT statement
    """
    # Safety: only allow SELECT statements
    stripped = query.strip().upper()
    if not stripped.startswith("SELECT"):
        raise ValueError("Only SELECT queries are allowed. Got: " + query[:50])

    engine = _get_engine()

    with engine.connect() as conn:
        result = conn.execute(text(query))
        columns = list(result.keys())
        rows = result.fetchall()

    # Apply column filtering based on role
    if role is not None:
        tables = _extract_tables(query)
        # Build union of allowed columns across all queried tables.
        # A column is shown if ANY table permits it (per-column, not intersection).
        all_table_allowed: set[str] = set()
        for table in tables:
            table_allowed = filter_columns(role, table, set(columns))
            all_table_allowed |= table_allowed  # union — column visible if any table allows it
        
        if all_table_allowed:
            col_indices = [i for i, c in enumerate(columns) if c in all_table_allowed]
            filtered_columns = [columns[i] for i in col_indices]
        else:
            col_indices = list(range(len(columns)))
            filtered_columns = columns
    else:
        col_indices = list(range(len(columns)))
        filtered_columns = columns

    # Convert to list of dicts with deterministic key order (canonical JSON)
    records = []
    for row in rows:
        record = {}
        for idx in col_indices:
            key = columns[idx]
            value = row[idx]
            # Convert non-serializable types
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            record[key] = value
        records.append(record)

    # Canonical JSON: sorted keys, deterministic output
    return json.dumps(records, sort_keys=True, default=str, ensure_ascii=False)


def get_table_schema() -> str:
    """Return the schema of all tables as a human-readable string."""
    engine = _get_engine()
    with engine.connect() as conn:
        result = conn.execute(text(
            "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"
        ))
        schemas = []
        for name, sql in result:
            schemas.append(f"-- {name}\n{sql}")
    return "\n\n".join(schemas)
