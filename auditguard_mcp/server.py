"""MCP server entrypoint — wires RBAC, PII scan, policy, tools, and audit together.

This is the compliance pipeline hub. Every tool call passes through:
  1. RBAC gate (1a: tool name, 1b: SQL parse, 1c: API validate)
  2. Inbound PII scan (Privacy Filter)
  3. Inbound policy engine
  4. Tool dispatch (with timeout)
  5. Outbound PII scan (Privacy Filter on canonical JSON)
  6. Outbound policy engine
  7. Audit logger

Runs via stdio transport: `python -m auditguard_mcp.server`
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from auditguard_mcp.audit import AuditLogger
from auditguard_mcp.models import (
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
from auditguard_mcp.policy import apply_policy, get_policy
from auditguard_mcp.privacy import detect, get_model_version
from auditguard_mcp.rbac import check_access
from auditguard_mcp.tools.sql_query import execute_sql
from auditguard_mcp.tools.customer_api import lookup_customer, search_customers

# New v2 pipeline imports
from auditguard_mcp.config import get_config
from auditguard_mcp.pipeline.types import AuditRequest, AuditContext, PolicyMode
from auditguard_mcp.pipeline.async_runner import run_audit_pipeline_async

# Optional Temporal import — only if backend is configured
try:
    from temporalio.client import Client as TemporalClient
    from auditguard_mcp.pipeline.temporal_runner import AuditPipelineWorkflow
    TEMPORAL_AVAILABLE = True
except ImportError:
    TEMPORAL_AVAILABLE = False

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

mcp = FastMCP(
    "auditguard-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)
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
# v2 Pipeline dispatch
# ---------------------------------------------------------------------------


async def _run_pipeline_v2(
    request: AuditRequest,
    context: AuditContext,
) -> tuple[str, dict | None]:
    """Dispatch to the configured backend (async or Temporal).

    Returns (tool_output, backend_meta). backend_meta is None for async,
    or a dict with workflow_id/run_id for Temporal.
    """
    config = get_config()

    if config.backend == "temporal":
        if not TEMPORAL_AVAILABLE:
            raise RuntimeError(
                "Temporal backend selected but temporalio not installed. "
                "Install with: pip install auditguard-mcp[temporal]"
            )
        return await _run_temporal(request, context)

    # Default: async backend
    result = await run_audit_pipeline_async(request, context)

    # Non-success statuses must return a meaningful error JSON so the
    # web UI and MCP clients can show "Access denied" instead of empty output.
    if result.status in ("rbac_denied", "blocked", "error") or result.error:
        if result.decisions and result.decisions[-1].sanitized_text:
            return result.decisions[-1].sanitized_text, {"backend": "async"}
        if result.error:
            return json.dumps({"error": result.error}), {"backend": "async"}
        return json.dumps({"error": result.status}), {"backend": "async"}

    return result.decisions[-1].sanitized_text if result.decisions else "", {"backend": "async"}


async def _run_temporal(
    request: AuditRequest,
    context: AuditContext,
) -> tuple[str, dict]:
    """Start a Temporal workflow and await the result.

    Returns (result_string, temporal_meta) where temporal_meta contains
    workflow_id, run_id, and a link to the Temporal UI.
    """
    config = get_config()
    client = await TemporalClient.connect(config.temporal_address)
    workflow_id = f"audit-{request.request_id}"
    handle = await client.start_workflow(
        AuditPipelineWorkflow.run,
        args=[request, context],
        id=workflow_id,
        task_queue=config.temporal_task_queue,
    )
    result = await handle.result()

    temporal_meta = {
        "backend": "temporal",
        "workflow_id": workflow_id,
        "run_id": handle.result_run_id,
        "task_queue": config.temporal_task_queue,
        "temporal_ui_url": f"http://localhost:8080/namespaces/default/workflows/{workflow_id}/{handle.result_run_id}",
    }

    if result.status in ("rbac_denied", "blocked", "error") or result.error:
        if result.decisions and result.decisions[-1].sanitized_text:
            return result.decisions[-1].sanitized_text, temporal_meta
        if result.error:
            return json.dumps({"error": result.error}), temporal_meta
        return json.dumps({"error": result.status}), temporal_meta

    return result.decisions[-1].sanitized_text if result.decisions else "", temporal_meta


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
    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role=Role(role),
        tool_name="sql_query",
        tool_input={"query": query},
        scan_text=query,
        requester=user_id,
    )
    context = AuditContext(
        policy_mode=PolicyMode.PERMISSIVE if role != "compliance_officer" else PolicyMode.STRICT,
    )
    result, _ = await _run_pipeline_v2(request, context)
    return result


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
    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role=Role(role),
        tool_name="customer_api_lookup",
        tool_input={"customer_id": customer_id},
        scan_text=f"Look up customer {customer_id}",
        requester=user_id,
    )
    context = AuditContext(
        policy_mode=PolicyMode.PERMISSIVE if role != "compliance_officer" else PolicyMode.STRICT,
    )
    result, _ = await _run_pipeline_v2(request, context)
    return result


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
    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role=Role(role),
        tool_name="customer_api_search",
        tool_input={"name": name, "email": email, "limit": limit},
        scan_text=f"Search customers: name={name}, email={email}",
        requester=user_id,
    )
    context = AuditContext(
        policy_mode=PolicyMode.PERMISSIVE if role != "compliance_officer" else PolicyMode.STRICT,
    )
    result, _ = await _run_pipeline_v2(request, context)
    return result


# ---------------------------------------------------------------------------
# Web Demo Tool — structured pipeline output for the frontend visualization
# ---------------------------------------------------------------------------


def _build_pipeline_view(audit: dict) -> dict:
    """Build per-layer pipeline state from an audit record for the 7-box visualization.

    Each layer returns {status: 'pass'|'transform'|'fail'|'skipped'|'pending',
                        label: str, detail: dict}

    Status meanings:
      pass      = step ran, nothing to act on (green)
      transform = step ran AND modified data (amber) — PII detected/redacted/hashed
      fail      = step blocked the request (red)
      skipped   = step never ran because an earlier step failed (grey)
    """
    status = audit.get("status", "success")

    rbac_denied = status == "rbac_denied"
    blocked = status == "blocked"
    executed = status in ("success", "review_queued")
    timed_out = status == "timeout"
    errored = status == "error"

    inbound_detections = audit.get("inbound_detections", [])
    outbound_detections = audit.get("outbound_detections", [])
    inbound_decisions = audit.get("policy_decisions_inbound", [])
    outbound_decisions = audit.get("policy_decisions_outbound", [])

    _ACTIVE_ACTIONS = {"redact", "hash", "vault", "review", "block"}

    def _has_active(decisions: list[dict]) -> bool:
        return any(d.get("action", "allow") in _ACTIVE_ACTIONS for d in decisions)

    layers = []

    # Layer 1: RBAC Gate
    layers.append({
        "status": "fail" if rbac_denied else "pass",
        "label": "RBAC Gate",
        "detail": {
            "policy": audit.get("policy_version", ""),
            "reason": "Access denied" if rbac_denied else "Access granted",
        }
    })

    # Layer 2: Inbound PII Scan
    inbound_ran = not rbac_denied
    n_in = len(inbound_detections) if inbound_ran else 0
    layers.append({
        "status": "skipped" if not inbound_ran else ("transform" if n_in > 0 else "pass"),
        "label": "Inbound PII",
        "detail": {
            "detections": n_in,
            "categories": list(set(d["category"] for d in inbound_detections)) if inbound_ran else [],
        }
    })

    # Layer 3: Inbound Policy Engine
    in_active = _has_active(inbound_decisions)
    layers.append({
        "status": "skipped" if not inbound_ran else ("fail" if blocked else ("transform" if in_active else "pass")),
        "label": "Inbound Policy",
        "detail": {
            "decisions": [{"category": d["category"], "action": d["action"]} for d in inbound_decisions] if inbound_ran else [],
        }
    })

    # Layer 4: Tool Execution
    tool_ran = executed or timed_out
    layers.append({
        "status": "pass" if executed else ("fail" if timed_out or errored else "skipped"),
        "label": "Execution",
        "detail": {
            "latency_ms": round(audit.get("latency_ms", 0), 1),
            "timed_out": timed_out,
        }
    })

    # Layer 5: Outbound PII Scan
    outbound_ran = tool_ran
    n_out = len(outbound_detections) if outbound_ran else 0
    layers.append({
        "status": "skipped" if not outbound_ran else ("transform" if n_out > 0 else "pass"),
        "label": "Outbound PII",
        "detail": {
            "detections": n_out,
            "categories": list(set(d["category"] for d in outbound_detections)) if outbound_ran else [],
        }
    })

    # Layer 6: Outbound Policy Engine
    out_active = _has_active(outbound_decisions)
    layers.append({
        "status": "skipped" if not outbound_ran else ("transform" if out_active else "pass"),
        "label": "Outbound Policy",
        "detail": {
            "decisions": [{"category": d["category"], "action": d["action"]} for d in outbound_decisions] if outbound_ran else [],
        }
    })

    # Layer 7: Audit Log
    layers.append({
        "status": "pass",
        "label": "Audit Log",
        "detail": {
            "request_id": audit.get("request_id", ""),
            "status": status,
            "review_queued": audit.get("review_queue_id") is not None,
        }
    })

    return {"steps": layers, "overall_status": status}


@mcp.tool()
async def demo_query(
    query: str,
    role: str = "analyst",
    sql: str = "",
    user_id: str = "demo-user",
) -> str:
    """Run a compliance pipeline query and return structured pipeline data.

    Designed for the web demo frontend. Returns JSON with per-layer pipeline
    state for the 7-box visualization, the tool result, and full audit record.

    Args:
        query: Natural-language description (shown in the UI)
        role: intern, analyst, or compliance_officer
        sql: The actual SQL query to execute through the pipeline
        user_id: User identifier
    """
    # Track audit log position before the call
    import os as _os
    audit_path = _os.environ.get("AUDIT_LOG_PATH", "./audit.jsonl")
    initial_lines = 0
    if _os.path.exists(audit_path):
        with open(audit_path) as f:
            initial_lines = len(f.readlines())

    sql_to_run = sql if sql else query

    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role=Role(role),
        tool_name="sql_query",
        tool_input={"query": sql_to_run},
        scan_text=sql_to_run,
        requester=user_id,
    )
    context = AuditContext(
        policy_mode=PolicyMode.PERMISSIVE if role != "compliance_officer" else PolicyMode.STRICT,
    )

    result, backend_meta = await _run_pipeline_v2(request, context)

    # Read the new audit record
    audit_record = None
    if _os.path.exists(audit_path):
        with open(audit_path) as f:
            all_lines = f.readlines()
        new_lines = all_lines[initial_lines:]
        if new_lines:
            import json as _json
            audit_record = _json.loads(new_lines[-1].strip())

    pipeline_view = _build_pipeline_view(audit_record) if audit_record else {
        "steps": [], "overall_status": "error"
    }

    return json.dumps({
        "pipeline": pipeline_view,
        "result": result,
        "audit": audit_record,
        "backend": backend_meta,
    })


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    """Run the MCP server via stdio transport."""
    logger.info("Starting auditguard-mcp server (stdio transport)...")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
