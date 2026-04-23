"""MCP server entrypoint — wires RBAC, PII scan, policy, tools, and audit together.

This is the compliance pipeline hub. Every tool call passes through:
  1. RBAC gate (1a: tool name, 1b: SQL parse, 1c: API validate)
  2. Inbound PII scan (Privacy Filter)
  3. Inbound policy engine
  4. Tool dispatch (with timeout)
  5. Outbound PII scan (Privacy Filter on canonical JSON)
  6. Outbound policy engine
  7. Audit logger

Runs via stdio transport: `python -m audited_tool_mcp.server`
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid

from mcp.server.fastmcp import FastMCP

from audited_tool_mcp.audit import AuditLogger
from audited_tool_mcp.models import (
    Actor,
    AuditRecord,
    Direction,
    PIIDetection,
    PolicyViolation,
    RBACDenied,
    RequestStatus,
    Role,
    sha256_hash,
)
from audited_tool_mcp.policy import apply_policy, get_policy
from audited_tool_mcp.privacy import detect, get_model_version
from audited_tool_mcp.rbac import check_access
from audited_tool_mcp.tools.sql_query import execute_sql
from audited_tool_mcp.tools.customer_api import lookup_customer, search_customers

# Configure logging to stderr (stdout is reserved for MCP JSON-RPC)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP("audited-tool-mcp")
audit_logger = AuditLogger()

# Default tool timeout in seconds
TOOL_TIMEOUT = 30.0


async def _process_pipeline(
    actor: Actor,
    tool_name: str,
    query: str,
    tool_executor,
    sql_query: str | None = None,
    api_endpoint: str | None = None,
    api_params: dict | None = None,
) -> str:
    """Execute the full 7-layer compliance pipeline.

    This is the shared pipeline function called by all MCP tools.
    Returns the final (possibly redacted) tool output.
    """
    request_id = str(uuid.uuid4())
    start_time = time.monotonic()

    # Initialize audit record fields
    inbound_detections: list[PIIDetection] = []
    policy_decisions_inbound = []
    tool_input_after_policy = query
    tool_output_raw_hash = ""
    outbound_detections: list[PIIDetection] = []
    policy_decisions_outbound = []
    tool_output_final = ""
    status = RequestStatus.SUCCESS
    review_queue_id: str | None = None
    policy_version = ""

    try:
        # ---------------------------------------------------------------
        # Layer 1: RBAC gate
        # ---------------------------------------------------------------
        permissions = check_access(
            actor, tool_name,
            sql_query=sql_query,
            api_endpoint=api_endpoint,
            api_params=api_params,
        )
        policy_config = get_policy(permissions.policy_name)
        policy_version = policy_config.version

        # ---------------------------------------------------------------
        # Layer 2: Inbound PII scan
        # ---------------------------------------------------------------
        inbound_detections = detect(query)

        # ---------------------------------------------------------------
        # Layer 3: Inbound policy engine
        # ---------------------------------------------------------------
        inbound_result = apply_policy(
            text=query,
            detections=inbound_detections,
            policy=policy_config,
            direction=Direction.INBOUND,
            request_id=request_id,
            actor=actor,
            tool_name=tool_name,
        )
        tool_input_after_policy = inbound_result.mutated_text
        policy_decisions_inbound = inbound_result.decisions

        if inbound_result.has_review_flag:
            review_queue_id = inbound_result.review_queue_id
            status = RequestStatus.REVIEW_QUEUED

        # ---------------------------------------------------------------
        # Layer 4: Tool dispatch (with timeout)
        # ---------------------------------------------------------------
        try:
            raw_output = await asyncio.wait_for(
                tool_executor(tool_input_after_policy),
                timeout=TOOL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            status = RequestStatus.TIMEOUT
            tool_output_final = json.dumps({
                "error": f"Tool '{tool_name}' timed out after {TOOL_TIMEOUT}s"
            })
            _emit_audit(
                request_id, actor, tool_name, query, inbound_detections,
                policy_decisions_inbound, tool_input_after_policy,
                tool_output_raw_hash, outbound_detections,
                policy_decisions_outbound, tool_output_final, status,
                start_time, review_queue_id, policy_version,
            )
            return tool_output_final

        tool_output_raw_hash = sha256_hash(raw_output)

        # ---------------------------------------------------------------
        # Layer 5: Outbound PII scan (on canonical JSON)
        # ---------------------------------------------------------------
        outbound_detections = detect(raw_output)

        # ---------------------------------------------------------------
        # Layer 6: Outbound policy engine
        # ---------------------------------------------------------------
        outbound_result = apply_policy(
            text=raw_output,
            detections=outbound_detections,
            policy=policy_config,
            direction=Direction.OUTBOUND,
            request_id=request_id,
            actor=actor,
            tool_name=tool_name,
        )
        tool_output_final = outbound_result.mutated_text
        policy_decisions_outbound = outbound_result.decisions

        if outbound_result.has_review_flag and review_queue_id is None:
            review_queue_id = outbound_result.review_queue_id
            status = RequestStatus.REVIEW_QUEUED

    except RBACDenied as e:
        status = RequestStatus.RBAC_DENIED
        tool_output_final = json.dumps({"error": str(e)})
        logger.warning("RBAC denied: %s", e)

    except PolicyViolation as e:
        status = RequestStatus.BLOCKED
        tool_output_final = json.dumps({"error": str(e)})
        logger.warning("Policy violation: %s", e)

    except Exception as e:
        status = RequestStatus.ERROR
        tool_output_final = json.dumps({"error": f"Internal error: {type(e).__name__}: {e}"})
        logger.exception("Pipeline error: %s", e)

    # -------------------------------------------------------------------
    # Layer 7: Audit logger
    # -------------------------------------------------------------------
    _emit_audit(
        request_id, actor, tool_name, query, inbound_detections,
        policy_decisions_inbound, tool_input_after_policy,
        tool_output_raw_hash, outbound_detections,
        policy_decisions_outbound, tool_output_final, status,
        start_time, review_queue_id, policy_version,
    )

    return tool_output_final


def _emit_audit(
    request_id, actor, tool_name, query, inbound_detections,
    policy_decisions_inbound, tool_input_after_policy,
    tool_output_raw_hash, outbound_detections,
    policy_decisions_outbound, tool_output_final, status,
    start_time, review_queue_id, policy_version,
):
    """Write the audit record."""
    latency_ms = (time.monotonic() - start_time) * 1000

    # Strip raw PII text from detections for the audit log
    safe_inbound = [
        PIIDetection(
            category=d.category,
            start=d.start,
            end=d.end,
            text=f"[{d.category.value}]",  # Replace raw text with category placeholder
            confidence=d.confidence,
        )
        for d in inbound_detections
    ]
    safe_outbound = [
        PIIDetection(
            category=d.category,
            start=d.start,
            end=d.end,
            text=f"[{d.category.value}]",
            confidence=d.confidence,
        )
        for d in outbound_detections
    ]

    record = AuditRecord(
        request_id=request_id,
        actor=actor,
        tool_name=tool_name,
        raw_query_hash=sha256_hash(query),
        inbound_detections=safe_inbound,
        policy_decisions_inbound=policy_decisions_inbound,
        tool_input_after_policy=tool_input_after_policy,
        tool_output_raw_hash=tool_output_raw_hash,
        outbound_detections=safe_outbound,
        policy_decisions_outbound=policy_decisions_outbound,
        tool_output_final=tool_output_final,
        status=status,
        latency_ms=latency_ms,
        review_queue_id=review_queue_id,
        policy_version=policy_version,
        model_version=get_model_version(),
    )

    audit_logger.log(record)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def sql_query(
    query: str,
    role: str = "analyst",
    user_id: str = "anonymous",
    session_id: str = "",
) -> str:
    """Execute a SQL query against the financial services database.

    The query passes through a compliance pipeline: RBAC check, PII detection,
    policy enforcement, and audit logging. Results may be redacted based on
    your role and the configured policy.

    Args:
        query: SQL SELECT query to execute
        role: Your role (intern, analyst, compliance_officer)
        user_id: Your user identifier
        session_id: Session identifier (auto-generated if empty)
    """
    actor = Actor(
        role=Role(role),
        user_id=user_id,
        session_id=session_id or str(uuid.uuid4()),
    )

    async def _execute(sanitized_query: str) -> str:
        return execute_sql(sanitized_query, role=actor.role)

    return await _process_pipeline(
        actor=actor,
        tool_name="sql_query",
        query=query,
        tool_executor=_execute,
        sql_query=query,  # Original query for RBAC SQL parsing
    )


@mcp.tool()
async def customer_lookup(
    customer_id: int,
    role: str = "analyst",
    user_id: str = "anonymous",
    session_id: str = "",
) -> str:
    """Look up a customer by ID via the internal Customer API.

    Returns customer details and their accounts. Results are filtered
    based on your role (e.g., analysts cannot see SSNs or full account numbers).

    Args:
        customer_id: The customer's database ID
        role: Your role (intern, analyst, compliance_officer)
        user_id: Your user identifier
        session_id: Session identifier (auto-generated if empty)
    """
    actor = Actor(
        role=Role(role),
        user_id=user_id,
        session_id=session_id or str(uuid.uuid4()),
    )

    query_text = f"Look up customer {customer_id}"

    async def _execute(sanitized_query: str) -> str:
        return await lookup_customer(customer_id, role=actor.role)

    return await _process_pipeline(
        actor=actor,
        tool_name="customer_api",
        query=query_text,
        tool_executor=_execute,
        api_endpoint=f"/customers/{customer_id}",
    )


@mcp.tool()
async def customer_search(
    name: str | None = None,
    email: str | None = None,
    role: str = "analyst",
    user_id: str = "anonymous",
    session_id: str = "",
    limit: int = 10,
) -> str:
    """Search for customers by name or email via the internal Customer API.

    Results are filtered based on your role. At least one search parameter
    (name or email) is required.

    Args:
        name: Search by customer name (partial match)
        email: Search by email (partial match)
        role: Your role (intern, analyst, compliance_officer)
        user_id: Your user identifier
        session_id: Session identifier (auto-generated if empty)
        limit: Maximum number of results (1-100)
    """
    actor = Actor(
        role=Role(role),
        user_id=user_id,
        session_id=session_id or str(uuid.uuid4()),
    )

    query_text = f"Search customers: name={name}, email={email}"

    async def _execute(sanitized_query: str) -> str:
        return await search_customers(name=name, email=email, role=actor.role, limit=limit)

    return await _process_pipeline(
        actor=actor,
        tool_name="customer_api",
        query=query_text,
        tool_executor=_execute,
        api_endpoint="/customers/search/",
        api_params={"name": name, "email": email} if name or email else None,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    """Run the MCP server via stdio transport."""
    logger.info("Starting audited-tool-mcp server (stdio transport)...")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
