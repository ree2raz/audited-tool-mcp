"""Tool registry — maps tool names to async callables.

All tools registered here are backend-agnostic. The pipeline executor calls
registered tools by name, passing a dict of kwargs and the caller's role.
"""
from __future__ import annotations

import asyncio
from typing import Any, Callable, Coroutine

from auditguard_mcp.models import Role
from auditguard_mcp.tools.sql_query import execute_sql
from auditguard_mcp.tools.customer_api import lookup_customer, search_customers

# Registry type: async callable that takes (tool_input: dict, role: Role) -> str
ToolCallable = Callable[[dict[str, Any], Role], Coroutine[Any, Any, str]]

TOOL_REGISTRY: dict[str, ToolCallable] = {}


async def sql_query_tool(tool_input: dict[str, Any], role: Role) -> str:
    """Execute a SQL query via the sql_query tool."""
    query = tool_input.get("query", "")
    return execute_sql(query, role=role)


async def customer_lookup_tool(tool_input: dict[str, Any], role: Role) -> str:
    """Look up a customer by ID via the customer_api tool."""
    customer_id = tool_input.get("customer_id")
    if customer_id is None:
        raise ValueError("customer_id is required for customer_lookup")
    return await lookup_customer(customer_id, role=role)


async def customer_search_tool(tool_input: dict[str, Any], role: Role) -> str:
    """Search customers via the customer_api tool."""
    name = tool_input.get("name")
    email = tool_input.get("email")
    limit = tool_input.get("limit", 10)
    return await search_customers(name=name, email=email, role=role, limit=limit)


# ---------------------------------------------------------------------------
# Default registrations
# ---------------------------------------------------------------------------

TOOL_REGISTRY["sql_query"] = sql_query_tool
TOOL_REGISTRY["customer_api_lookup"] = customer_lookup_tool
TOOL_REGISTRY["customer_api_search"] = customer_search_tool

# Alias for backward compatibility with existing server.py tools
TOOL_REGISTRY["customer_api"] = customer_lookup_tool
