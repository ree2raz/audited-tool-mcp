"""Customer API tool — FastAPI-based REST API serving synthetic customer data.

This runs as a separate process (replicating real-world deployment).
The tool function makes HTTP requests to the local API.

Server: start with `python -m audited_tool_mcp.tools.customer_api`
Tool:   call `lookup_customer()` or `search_customers()` from the MCP server
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from audited_tool_mcp.models import Role

logger = logging.getLogger(__name__)

_DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "synthetic_fs.sqlite"))
_API_BASE = os.environ.get("CUSTOMER_API_BASE", "http://localhost:8100")

# Fields restricted per role (applied server-side in tool, not in API)
_RESTRICTED_FIELDS: dict[Role, set[str]] = {
    Role.ANALYST: {"ssn", "account_number"},
}


# ---------------------------------------------------------------------------
# FastAPI application (runs as separate process)
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Synthetic Customer API",
    description="REST API for synthetic financial services customer data",
    version="0.1.0",
)


def _get_db() -> sqlite3.Connection:
    """Get a SQLite connection for the API."""
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.get("/customers/{customer_id}")
def get_customer(customer_id: int) -> dict:
    """Get a customer by ID with their accounts."""
    conn = _get_db()
    try:
        customer = conn.execute(
            "SELECT * FROM customers WHERE id = ?", (customer_id,)
        ).fetchone()
        if not customer:
            raise HTTPException(status_code=404, detail=f"Customer {customer_id} not found")

        accounts = conn.execute(
            "SELECT * FROM accounts WHERE customer_id = ?", (customer_id,)
        ).fetchall()

        return {
            "customer": dict(customer),
            "accounts": [dict(a) for a in accounts],
        }
    finally:
        conn.close()


@app.get("/customers/search/")
def search_customers(
    name: str | None = Query(None, description="Search by name (first or last)"),
    email: str | None = Query(None, description="Search by email"),
    limit: int = Query(10, ge=1, le=100),
) -> dict:
    """Search customers by name or email."""
    conn = _get_db()
    try:
        conditions = []
        params = []

        if name:
            conditions.append(
                "(first_name LIKE ? OR last_name LIKE ?)"
            )
            params.extend([f"%{name}%", f"%{name}%"])

        if email:
            conditions.append("email LIKE ?")
            params.append(f"%{email}%")

        if not conditions:
            raise HTTPException(
                status_code=400,
                detail="At least one search parameter (name or email) is required",
            )

        where_clause = " AND ".join(conditions)
        query = f"SELECT * FROM customers WHERE {where_clause} LIMIT ?"
        params.append(limit)

        results = conn.execute(query, params).fetchall()
        return {
            "results": [dict(r) for r in results],
            "count": len(results),
        }
    finally:
        conn.close()


@app.get("/health")
def health() -> dict:
    """Health check endpoint."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Tool functions (called from MCP server, make HTTP requests to the API)
# ---------------------------------------------------------------------------


async def lookup_customer(customer_id: int, role: Role | None = None) -> str:
    """Look up a customer by ID via the Customer API.

    Returns canonical JSON (sorted keys) for reproducible PII scanning.
    Applies field restrictions based on role.
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{_API_BASE}/customers/{customer_id}",
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.ConnectError:
            return json.dumps({"error": "Customer API is not running. Start it with: python -m audited_tool_mcp.tools.customer_api"})
        except httpx.HTTPStatusError as e:
            return json.dumps({"error": f"API error: {e.response.status_code} - {e.response.text}"})

    # Apply field restrictions
    if role is not None:
        restricted = _RESTRICTED_FIELDS.get(role, set())
        if restricted and "customer" in data:
            data["customer"] = {
                k: v for k, v in data["customer"].items() if k not in restricted
            }
        if restricted and "accounts" in data:
            data["accounts"] = [
                {k: v for k, v in acct.items() if k not in restricted}
                for acct in data["accounts"]
            ]

    return json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)


async def search_customers(
    name: str | None = None,
    email: str | None = None,
    role: Role | None = None,
    limit: int = 10,
) -> str:
    """Search customers via the Customer API.

    Returns canonical JSON (sorted keys) for reproducible PII scanning.
    Applies field restrictions based on role.
    """
    params: dict[str, Any] = {"limit": limit}
    if name:
        params["name"] = name
    if email:
        params["email"] = email

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(
                f"{_API_BASE}/customers/search/",
                params=params,
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.ConnectError:
            return json.dumps({"error": "Customer API is not running. Start it with: python -m audited_tool_mcp.tools.customer_api"})
        except httpx.HTTPStatusError as e:
            return json.dumps({"error": f"API error: {e.response.status_code} - {e.response.text}"})

    # Apply field restrictions
    if role is not None:
        restricted = _RESTRICTED_FIELDS.get(role, set())
        if restricted and "results" in data:
            data["results"] = [
                {k: v for k, v in customer.items() if k not in restricted}
                for customer in data["results"]
            ]

    return json.dumps(data, sort_keys=True, default=str, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Run as standalone FastAPI server
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("CUSTOMER_API_PORT", "8100"))
    print(f"Starting Customer API on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
