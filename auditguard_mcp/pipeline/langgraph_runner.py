"""LangGraph backend -- graph-native orchestration of the 7-stage audit pipeline.

Why LangGraph:
- Explicit graph topology makes branching logic inspectable and testable
- Conditional edges encode short-circuit rules without nested if-else chains
- Graph compilation validates routing before runtime
- Future: add a checkpointer (SqliteSaver / PostgresSaver) for cross-process
  durability, streaming node events, or LangSmith tracing -- no restructuring
  needed

Tradeoffs vs async backend:
- Small overhead from graph compilation and state serialization (~1-5ms)
- Extra dependencies (langgraph, langchain-core)
- Same durability gap as async: no cross-process persistence without a
  checkpointer

Tradeoffs vs Temporal:
- No built-in durable retry across worker crashes (Temporal's core value)
- No human-in-the-loop signal mechanism (implemented as immediate short-circuit)
- Much simpler operationally -- no Temporal cluster required
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any, TypedDict

from langgraph.graph import StateGraph, END

from auditguard_mcp.models import PIIDetection, RBACDenied, RequestStatus

from .stages import (
    apply_inbound_policy,
    apply_outbound_policy,
    check_rbac,
    execute_bounded,
    scan_inbound_pii,
    scan_outbound_pii,
    write_audit_log,
)
from .types import (
    AuditContext,
    AuditRequest,
    PIIScanResult,
    PipelineAction,
    PipelineDecision,
    PipelineLogEntry,
)


# ============================================================================
# Pipeline state -- the shared bag passed between nodes
# ============================================================================

class PipelineState(TypedDict, total=False):
    """Mutable state threaded through the graph.

    Each node receives the full state and returns a partial dict of updates.
    LangGraph merges returned updates into the state by key overwrite.
    """
    request: AuditRequest
    context: AuditContext

    # Accumulated scan results
    inbound_pii: PIIScanResult | None
    outbound_pii: PIIScanResult | None

    # Deserialized detection objects for audit log
    inbound_detections: list[PIIDetection] | None
    outbound_detections: list[PIIDetection] | None

    # Growing list of stage decisions (inbound, then outbound)
    decisions: list[PipelineDecision]

    # Tool output after execution
    output: str | None

    # Pipeline-level status and error
    status: RequestStatus
    error: str | None

    # Monotonic start time for duration calculation
    start_time: float

    # Routing signal read by conditional edges
    # Values: "continue" | "short_circuit" | "rbac_denied" | "human_review"
    route: str

    # Final result populated by the audit_log node
    log_entry: PipelineLogEntry | None


# ============================================================================
# Nodes -- one per pipeline stage
# ============================================================================

async def node_rbac(state: PipelineState) -> dict[str, Any]:
    """Stage 1: RBAC check. Short-circuits to audit_log on denial."""
    request = state["request"]
    context = state["context"]
    try:
        await asyncio.to_thread(check_rbac, request, context)
        return {"route": "continue"}
    except RBACDenied as e:
        error_msg = str(e)
        denial = PipelineDecision(
            action=PipelineAction.DENY,
            reason=error_msg,
            triggered_rules=["rbac"],
            sanitized_text=json.dumps({"error": error_msg}),
            categories=[],
        )
        return {
            "decisions": [denial],
            "status": RequestStatus.RBAC_DENIED,
            "error": error_msg,
            "route": "rbac_denied",
        }


async def node_scan_inbound(state: PipelineState) -> dict[str, Any]:
    """Stage 2: Inbound PII scan."""
    pii = await asyncio.to_thread(scan_inbound_pii, state["request"], state["context"])
    detections = [PIIDetection.model_validate(d) for d in pii.detections]
    return {
        "inbound_pii": pii,
        "inbound_detections": detections,
    }


async def node_policy_inbound(state: PipelineState) -> dict[str, Any]:
    """Stage 3: Inbound policy. Sets route for conditional edge."""
    decision = await asyncio.to_thread(
        apply_inbound_policy,
        state["request"],
        state["inbound_pii"],
        state["context"],
    )
    decisions = list(state.get("decisions") or [])
    decisions.append(decision)

    if decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
        return {
            "decisions": decisions,
            "status": RequestStatus.BLOCKED,
            "error": "Inbound policy denied or blocked the request",
            "route": "short_circuit",
        }
    if decision.action == PipelineAction.HUMAN_REVIEW:
        # Async backend parity: queue review and return immediately
        return {
            "decisions": decisions,
            "status": RequestStatus.REVIEW_QUEUED,
            "error": "Human review required (langgraph backend cannot wait)",
            "route": "human_review",
        }
    return {"decisions": decisions, "route": "continue"}


async def node_execute(state: PipelineState) -> dict[str, Any]:
    """Stage 4: Bounded tool execution."""
    inbound_decision = state["decisions"][-1]
    output = await execute_bounded(state["request"], inbound_decision, state["context"])
    return {"output": output}


async def node_scan_outbound(state: PipelineState) -> dict[str, Any]:
    """Stage 5: Outbound PII scan."""
    output = state.get("output") or ""
    pii = await asyncio.to_thread(scan_outbound_pii, output, state["context"])
    detections = [PIIDetection.model_validate(d) for d in pii.detections]
    return {
        "outbound_pii": pii,
        "outbound_detections": detections,
    }


async def node_policy_outbound(state: PipelineState) -> dict[str, Any]:
    """Stage 6: Outbound policy."""
    output = state.get("output") or ""
    decision = await asyncio.to_thread(
        apply_outbound_policy,
        output,
        state["outbound_pii"],
        state["context"],
    )
    decisions = list(state.get("decisions") or [])
    decisions.append(decision)

    updates: dict[str, Any] = {"decisions": decisions}
    if decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
        updates["status"] = RequestStatus.BLOCKED
        updates["output"] = decision.sanitized_text
    return updates


async def node_audit_log(state: PipelineState) -> dict[str, Any]:
    """Stage 7: Write structured audit log. Always runs -- terminal node."""
    request = state["request"]
    context = state["context"]
    decisions = state.get("decisions") or []
    start_time = state["start_time"]
    duration_ms = int((time.monotonic() - start_time) * 1000)

    log_entry = write_audit_log(
        request=request,
        output=state.get("output"),
        decisions=decisions,
        context=context,
        duration_ms=duration_ms,
        backend="langgraph",
        inbound_detections=state.get("inbound_detections"),
        outbound_detections=state.get("outbound_detections"),
        status=state.get("status", RequestStatus.SUCCESS),
        error=state.get("error"),
    )
    return {"log_entry": log_entry}


# ============================================================================
# Routing functions -- read the route key from state
# ============================================================================

def route_after_rbac(state: PipelineState) -> str:
    return "audit_log" if state["route"] == "rbac_denied" else "scan_inbound"


def route_after_policy_inbound(state: PipelineState) -> str:
    route = state["route"]
    if route in ("short_circuit", "human_review"):
        return "audit_log"
    return "execute"


# ============================================================================
# Graph construction
# ============================================================================

def _build_graph() -> Any:
    graph = StateGraph(PipelineState)

    graph.add_node("rbac", node_rbac)
    graph.add_node("scan_inbound", node_scan_inbound)
    graph.add_node("policy_inbound", node_policy_inbound)
    graph.add_node("execute", node_execute)
    graph.add_node("scan_outbound", node_scan_outbound)
    graph.add_node("policy_outbound", node_policy_outbound)
    graph.add_node("audit_log", node_audit_log)

    graph.set_entry_point("rbac")

    graph.add_conditional_edges(
        "rbac",
        route_after_rbac,
        {"scan_inbound": "scan_inbound", "audit_log": "audit_log"},
    )
    graph.add_edge("scan_inbound", "policy_inbound")
    graph.add_conditional_edges(
        "policy_inbound",
        route_after_policy_inbound,
        {"execute": "execute", "audit_log": "audit_log"},
    )
    graph.add_edge("execute", "scan_outbound")
    graph.add_edge("scan_outbound", "policy_outbound")
    graph.add_edge("policy_outbound", "audit_log")
    graph.add_edge("audit_log", END)

    return graph.compile()


# Module-level compiled graph (built once, reused across calls)
_PIPELINE_GRAPH = _build_graph()


# ============================================================================
# Public entrypoint
# ============================================================================

async def run_audit_pipeline_langgraph(
    request: AuditRequest,
    context: AuditContext,
) -> PipelineLogEntry:
    """Runs the 7-stage audit pipeline as a LangGraph StateGraph.

    Semantically equivalent to run_audit_pipeline_async: same stages, same
    branching rules, same audit log format. Differences are in how control
    flow is expressed (explicit graph edges vs. imperative if-else).
    """
    initial_state: PipelineState = {
        "request": request,
        "context": context,
        "decisions": [],
        "inbound_pii": None,
        "outbound_pii": None,
        "inbound_detections": None,
        "outbound_detections": None,
        "output": None,
        "status": RequestStatus.SUCCESS,
        "error": None,
        "start_time": time.monotonic(),
        "route": "continue",
        "log_entry": None,
    }

    # Stream values so we always hold the latest merged state.
    # If a node raises mid-pipeline, last_state preserves every decision and
    # detection accumulated before the crash -- not the empty initial_state.
    last_state: PipelineState = initial_state
    try:
        async for snapshot in _PIPELINE_GRAPH.astream(initial_state, stream_mode="values"):
            last_state = snapshot
    except Exception as e:
        error_msg = f"{type(e).__name__}: {e}"
        duration_ms = int((time.monotonic() - initial_state["start_time"]) * 1000)
        return write_audit_log(
            request=request,
            output=last_state.get("output"),
            decisions=last_state.get("decisions") or [],
            context=context,
            duration_ms=duration_ms,
            backend="langgraph",
            inbound_detections=last_state.get("inbound_detections"),
            outbound_detections=last_state.get("outbound_detections"),
            status=RequestStatus.ERROR,
            error=error_msg,
        )

    log_entry = last_state.get("log_entry")
    if log_entry is None:
        raise RuntimeError("LangGraph pipeline completed without a log entry")

    return log_entry
