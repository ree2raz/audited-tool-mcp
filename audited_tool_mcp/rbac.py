"""Role-based access control — the cheapest denial path in the pipeline.

Three roles for v1: intern, analyst, compliance_officer.
RBAC check happens BEFORE PII scan. Three sub-checks, ordered cheapest first:
  1a. O(1) set membership: tool_name in role.allowed_tools
  1b. For sql_query: parse SQL, validate tables/columns
  1c. For customer_api: validate endpoint + params
"""

from __future__ import annotations

import logging
import re

from audited_tool_mcp.models import (
    Actor,
    RBACDenied,
    Role,
    RolePermissions,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role definitions
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[Role, RolePermissions] = {
    Role.INTERN: RolePermissions(
        allowed_tools=set(),
        allowed_tables=set(),
        allowed_columns={},
        policy_name="",  # No policy needed — all requests blocked
    ),
    Role.ANALYST: RolePermissions(
        allowed_tools={"sql_query", "customer_api"},
        allowed_tables={"customers", "accounts", "transactions", "advisors"},
        allowed_columns={
            # For each table, specify which columns are allowed.
            # Empty set or missing key means all columns are allowed.
            "customers": {
                "id", "first_name", "last_name", "email", "phone",
                "address", "date_of_birth",
                # Explicitly EXCLUDED: "ssn"
            },
            "accounts": {
                "id", "customer_id", "account_type", "balance", "opened_date",
                # Explicitly EXCLUDED: "account_number" (full number)
            },
            "transactions": {
                "id", "account_id", "amount", "description", "timestamp", "counterparty",
            },
            "advisors": {
                "id", "name", "email", "phone", "region",
            },
        },
        policy_name="permissive_analyst",
    ),
    Role.COMPLIANCE_OFFICER: RolePermissions(
        allowed_tools={"sql_query", "customer_api"},
        allowed_tables={"customers", "accounts", "transactions", "advisors"},
        allowed_columns={},  # Empty = all columns allowed
        policy_name="strict_financial",
    ),
}

# Columns that are restricted for certain roles
_RESTRICTED_COLUMNS: dict[str, set[str]] = {
    "customers": {"ssn"},
    "accounts": {"account_number"},
}

# API endpoints and restricted fields per role
_API_RESTRICTED_FIELDS: dict[Role, set[str]] = {
    Role.ANALYST: {"ssn", "account_number"},
}


# ---------------------------------------------------------------------------
# SQL parsing (lightweight — not a full parser)
# ---------------------------------------------------------------------------

# Simple regex to extract table names from SQL
_TABLE_PATTERN = re.compile(
    r"\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+(\w+)",
    re.IGNORECASE,
)

# Simple regex to extract column names from SELECT
_SELECT_COLUMNS_PATTERN = re.compile(
    r"SELECT\s+(.*?)\s+FROM",
    re.IGNORECASE | re.DOTALL,
)


def _extract_tables(sql: str) -> set[str]:
    """Extract table names from a SQL query (best-effort, not a full parser)."""
    return {m.group(1).lower() for m in _TABLE_PATTERN.finditer(sql)}


def _extract_select_columns(sql: str) -> set[str] | None:
    """Extract column names from a SELECT statement.

    Returns None if it's SELECT * (meaning all columns).
    Returns a set of column names otherwise.
    """
    match = _SELECT_COLUMNS_PATTERN.search(sql)
    if not match:
        return None

    cols_str = match.group(1).strip()
    if cols_str == "*":
        return None  # SELECT * — need to check all columns after execution

    # Split on commas, strip whitespace, handle "table.column" format
    columns = set()
    for col in cols_str.split(","):
        col = col.strip()
        # Remove table prefix if present (e.g., "customers.ssn" → "ssn")
        if "." in col:
            col = col.split(".")[-1]
        # Remove aliases (e.g., "ssn AS social" → "ssn")
        if " as " in col.lower():
            col = col.split()[0]
        # Remove aggregate functions (e.g., "COUNT(id)" → "id")
        func_match = re.match(r"\w+\((\w+)\)", col)
        if func_match:
            col = func_match.group(1)
        columns.add(col.lower().strip())

    return columns


def validate_sql_access(role: Role, sql: str) -> None:
    """Validate that the SQL query only accesses tables/columns allowed for the role.

    Raises RBACDenied if any table or column is restricted.
    """
    permissions = ROLE_PERMISSIONS[role]

    # Check tables
    tables = _extract_tables(sql)
    for table in tables:
        if permissions.allowed_tables and table not in permissions.allowed_tables:
            raise RBACDenied(
                role=role,
                tool_name="sql_query",
                reason=f"Table '{table}' is not accessible for role '{role.value}'",
            )

    # Check columns
    columns = _extract_select_columns(sql)
    if columns is not None:
        for table in tables:
            allowed_cols = permissions.allowed_columns.get(table)
            if allowed_cols:  # If there's a column restriction for this table
                for col in columns:
                    if col not in allowed_cols and col in _RESTRICTED_COLUMNS.get(table, set()):
                        raise RBACDenied(
                            role=role,
                            tool_name="sql_query",
                            reason=(
                                f"Column '{col}' in table '{table}' is restricted "
                                f"for role '{role.value}'"
                            ),
                        )


def validate_api_access(role: Role, endpoint: str, params: dict | None = None) -> None:
    """Validate that the API access is allowed for the role.

    For v1, this checks that restricted fields are not being requested.
    """
    restricted = _API_RESTRICTED_FIELDS.get(role, set())
    if not restricted:
        return

    # Check if any restricted field is being requested in the params
    if params:
        requested_fields = params.get("fields", [])
        if isinstance(requested_fields, str):
            requested_fields = [f.strip() for f in requested_fields.split(",")]
        for field in requested_fields:
            if field.lower() in restricted:
                raise RBACDenied(
                    role=role,
                    tool_name="customer_api",
                    reason=f"Field '{field}' is restricted for role '{role.value}'",
                )


# ---------------------------------------------------------------------------
# Main RBAC check
# ---------------------------------------------------------------------------


def check_access(
    actor: Actor,
    tool_name: str,
    sql_query: str | None = None,
    api_endpoint: str | None = None,
    api_params: dict | None = None,
) -> RolePermissions:
    """Three-step RBAC check, ordered cheapest first.

    1a. O(1) set membership: tool_name in role.allowed_tools
    1b. For sql_query: parse SQL, validate tables/columns
    1c. For customer_api: validate endpoint + params

    Returns the RolePermissions if access is granted.
    Raises RBACDenied if any check fails.
    """
    permissions = ROLE_PERMISSIONS.get(actor.role)
    if permissions is None:
        raise RBACDenied(
            role=actor.role,
            tool_name=tool_name,
            reason=f"Unknown role: {actor.role.value}",
        )

    # Step 1a: Tool name check (O(1))
    if tool_name not in permissions.allowed_tools:
        raise RBACDenied(
            role=actor.role,
            tool_name=tool_name,
            reason=(
                f"Role '{actor.role.value}' does not have access to tool '{tool_name}'. "
                f"Allowed tools: {permissions.allowed_tools or 'none'}"
            ),
        )

    # Step 1b: SQL access check (only if applicable)
    if tool_name == "sql_query" and sql_query is not None:
        validate_sql_access(actor.role, sql_query)

    # Step 1c: API access check (only if applicable)
    if tool_name == "customer_api" and api_endpoint is not None:
        validate_api_access(actor.role, api_endpoint, api_params)

    logger.debug(
        "RBAC granted: role=%s, tool=%s", actor.role.value, tool_name
    )
    return permissions


def get_restricted_columns(role: Role, table: str) -> set[str]:
    """Get columns that are restricted for a role in a given table."""
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        return set()

    allowed = permissions.allowed_columns.get(table)
    if not allowed:
        return set()  # No restrictions

    all_restricted = _RESTRICTED_COLUMNS.get(table, set())
    return all_restricted - allowed


def filter_columns(role: Role, table: str, columns: set[str]) -> set[str]:
    """Filter a set of columns to only those allowed for the role."""
    permissions = ROLE_PERMISSIONS.get(role)
    if permissions is None:
        return set()

    allowed = permissions.allowed_columns.get(table)
    if not allowed:
        return columns  # No column restrictions — all allowed

    return columns & allowed
