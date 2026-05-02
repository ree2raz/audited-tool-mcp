"""Stage implementations for the audit pipeline.

Backend-agnostic -- used by both async and Temporal runners.
Each stage is a pure function (or thin wrapper) that takes data in and
returns data out. No global state mutations except audit log writes.
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from auditguard_mcp.audit import AuditLogger
from auditguard_mcp.models import (
    Actor,
    AuditRecord,
    Direction,
    PIIDetection,
    PolicyConfig,
    RequestStatus,
    RBACDenied,
    PolicyViolation,
    Role,
)
from auditguard_mcp.privacy import detect, get_model_version
from auditguard_mcp.policy import apply_policy, get_policy
from auditguard_mcp.rbac import check_access
from auditguard_mcp.tools.registry import TOOL_REGISTRY

from .types import (
    AuditRequest,
    AuditContext,
    PIIScanResult,
    PipelineAction,
    PipelineDecision,
    PipelineLogEntry,
    PolicyMode,
)

# Module-level audit logger
_audit_logger = AuditLogger()


def _get_policy_config(context: AuditContext) -> PolicyConfig:
    """Resolve the concrete PolicyConfig from the high-level mode."""
    if context.policy_mode == PolicyMode.STRICT:
        return get_policy("strict_financial")
    return get_policy("permissive_analyst")


def _actor_from_request(request: AuditRequest) -> Actor:
    """Build an Actor from an AuditRequest."""
    return Actor(
        role=request.role,
        user_id=request.requester,
        session_id=request.request_id,
    )


def _safe_detections(detections: list[PIIDetection]) -> list[PIIDetection]:
    """Strip raw text from detections for audit log safety."""
    return [
        PIIDetection(
            category=d.category,
            start=d.start,
            end=d.end,
            text=f"[{d.category.value}]",
            confidence=d.confidence,
        )
        for d in detections
    ]


def _map_sanitized_to_pipeline_decision(
    sanitized: Any,
    default_text: str,
) -> PipelineDecision:
    """Map a SanitizedInput result to a pipeline-level decision."""
    from auditguard_mcp.models import SanitizedInput
    assert isinstance(sanitized, SanitizedInput)

    # Determine aggregate action
    if sanitized.has_review_flag:
        action = PipelineAction.HUMAN_REVIEW
    elif sanitized.mutations:
        action = PipelineAction.TRANSFORM
    else:
        action = PipelineAction.ALLOW

    # Collect triggered rules (mutation reasons)
    triggered = list({m.action.value for m in sanitized.mutations})

    # Build a human-readable reason
    if action == PipelineAction.HUMAN_REVIEW:
        reason = "Human review required for flagged PII categories"
    elif action == PipelineAction.TRANSFORM:
        reason = f"Applied {len(sanitized.mutations)} mutations: {', '.join(triggered)}"
    else:
        reason = "No PII policy actions triggered"

    return PipelineDecision(
        action=action,
        reason=reason,
        triggered_rules=triggered,
        sanitized_text=sanitized.mutated_text,
        has_review_flag=sanitized.has_review_flag,
        review_queue_id=sanitized.review_queue_id,
    )


# ============================================================================
# Stage 1: RBAC check
# ============================================================================

def check_rbac(request: AuditRequest, context: AuditContext) -> None:
    """Validates the requesting role has permission for this tool.

    Pure function, no side effects.
    Raises: RBACDenied if role lacks permission.
    """
    actor = _actor_from_request(request)
    check_access(
        actor,
        request.tool_name,
        # Pass SQL query if present for SQL parsing
        sql_query=request.tool_input.get("query")
        if request.tool_name == "sql_query"
        else None,
        # Pass API endpoint/params if present
        api_endpoint=request.tool_input.get("api_endpoint")
        if request.tool_name in ("customer_api", "customer_api_lookup", "customer_api_search")
        else None,
        api_params=request.tool_input if request.tool_name in ("customer_api", "customer_api_lookup", "customer_api_search") else None,
    )


# ============================================================================
# Stage 2: Inbound PII scan
# ============================================================================

def scan_inbound_pii(request: AuditRequest, context: AuditContext) -> PIIScanResult:
    """Scans inbound payload using OpenAI Privacy Filter.

    This is the IO-heavy stage -- model inference.
    Raises: Nothing (returns empty result on empty text).
    """
    text = request.scan_text or ""
    if not text.strip():
        return PIIScanResult(has_pii=False, confidence=0.0)

    detections = detect(text)

    # Apply threshold filtering
    filtered = [d for d in detections if d.confidence >= context.pii_threshold]

    if not filtered:
        return PIIScanResult(has_pii=False, confidence=0.0)

    return PIIScanResult(
        has_pii=True,
        confidence=max(d.confidence for d in filtered),
        detected_types=list({d.category.value for d in filtered}),
        detections=[d.model_dump() for d in filtered],
    )


# ============================================================================
# Stage 3: Role-specific policy check (inbound)
# ============================================================================

def apply_inbound_policy(
    request: AuditRequest,
    pii_result: PIIScanResult,
    context: AuditContext,
) -> PipelineDecision:
    """Applies role-specific policy to inbound text.

    Returns PipelineDecision with action:
      - ALLOW: no PII or all ALLOW actions
      - TRANSFORM: text was mutated (REDACT/HASH/VAULT)
      - HUMAN_REVIEW: REVIEW action triggered
      - BLOCK: BLOCK action triggered (PolicyViolation caught)
    """
    text = request.scan_text or ""
    policy = _get_policy_config(context)
    actor = _actor_from_request(request)

    # Reconstruct PIIDetection objects from serializable dicts
    detections = [PIIDetection.model_validate(d) for d in pii_result.detections]

    try:
        sanitized = apply_policy(
            text=text,
            detections=detections,
            policy=policy,
            direction=Direction.INBOUND,
            request_id=request.request_id,
            actor=actor,
            tool_name=request.tool_name,
        )
    except PolicyViolation as e:
        return PipelineDecision(
            action=PipelineAction.BLOCK,
            reason=f"Policy violation (inbound): {e.reason}",
            triggered_rules=[e.category.value],
            sanitized_text=text,
        )

    return _map_sanitized_to_pipeline_decision(sanitized, text)


# ============================================================================
# Stage 4: Bounded execution
# ============================================================================

async def execute_bounded(
    request: AuditRequest,
    decision: PipelineDecision,
    context: AuditContext,
) -> str:
    """Executes the underlying tool call within bounded constraints.

    Looks up the tool in the registry and calls it with the tool_input dict.
    The decision.sanitized_text may be used for tools that take a single text
    argument (e.g., sql_query).
    """
    import asyncio

    tool_name = request.tool_name
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"Unknown tool: {tool_name}")

    tool_fn = TOOL_REGISTRY[tool_name]

    # For sql_query, replace the query text with the sanitized version
    tool_input = dict(request.tool_input)
    if tool_name == "sql_query" and decision.sanitized_text:
        tool_input["query"] = decision.sanitized_text

    # Run with timeout
    try:
        output = await asyncio.wait_for(
            tool_fn(tool_input, request.role),
            timeout=context.timeout_seconds,
        )
    except asyncio.TimeoutError:
        raise TimeoutError(
            f"Tool '{tool_name}' timed out after {context.timeout_seconds}s"
        )

    # Truncate if too large
    if len(output) > context.max_output_tokens:
        output = output[: context.max_output_tokens] + "\n... [truncated]"

    return output


# ============================================================================
# Stage 5: Outbound PII scan
# ============================================================================

def scan_outbound_pii(output: str, context: AuditContext) -> PIIScanResult:
    """Scans tool output for PII before returning to client."""
    if not output or not output.strip():
        return PIIScanResult(has_pii=False, confidence=0.0)

    detections = detect(output)
    filtered = [d for d in detections if d.confidence >= context.pii_threshold]

    if not filtered:
        return PIIScanResult(has_pii=False, confidence=0.0)

    return PIIScanResult(
        has_pii=True,
        confidence=max(d.confidence for d in filtered),
        detected_types=list({d.category.value for d in filtered}),
        detections=[d.model_dump() for d in filtered],
    )


# ============================================================================
# Stage 6: Outbound policy check
# ============================================================================

def apply_outbound_policy(
    output: str,
    pii_result: PIIScanResult,
    context: AuditContext,
) -> PipelineDecision:
    """Applies policy to outbound tool output."""
    policy = _get_policy_config(context)
    detections = [PIIDetection.model_validate(d) for d in pii_result.detections]

    try:
        sanitized = apply_policy(
            text=output,
            detections=detections,
            policy=policy,
            direction=Direction.OUTBOUND,
            request_id="",  # outbound uses original request_id from inbound log
            actor=Actor(role=Role.ANALYST, user_id="system"),
            tool_name="",
        )
    except PolicyViolation as e:
        return PipelineDecision(
            action=PipelineAction.BLOCK,
            reason=f"Policy violation (outbound): {e.reason}",
            triggered_rules=[e.category.value],
            sanitized_text=output,
        )

    return _map_sanitized_to_pipeline_decision(sanitized, output)


# ============================================================================
# Stage 7: Audit log write
# ============================================================================

def write_audit_log(
    request: AuditRequest,
    output: str | None,
    decisions: list[PipelineDecision],
    context: AuditContext,
    duration_ms: int,
    backend: str,
    inbound_detections: list[PIIDetection] | None = None,
    outbound_detections: list[PIIDetection] | None = None,
    status: RequestStatus = RequestStatus.SUCCESS,
    error: str | None = None,
) -> PipelineLogEntry:
    """Writes structured JSONL audit entry with full event history.

    This is the durability anchor -- must succeed even on partial failures.
    Returns the log entry for the caller to include in responses.
    """
    actor = _actor_from_request(request)
    policy = _get_policy_config(context)

    # Determine final action from decisions
    final_action = PipelineAction.ALLOW
    for d in decisions:
        if d.action in (PipelineAction.BLOCK, PipelineAction.DENY):
            final_action = d.action
            break
        elif d.action == PipelineAction.HUMAN_REVIEW:
            final_action = PipelineAction.HUMAN_REVIEW

    from auditguard_mcp.models import PolicyDecision as ExistingPolicyDecision, PIICategory

    _action_map = {
        PipelineAction.ALLOW: "allow",
        PipelineAction.TRANSFORM: "redact",
        PipelineAction.DENY: "block",
        PipelineAction.BLOCK: "block",
        PipelineAction.HUMAN_REVIEW: "review",
        PipelineAction.AUDIT_AND_ALLOW: "allow",
    }

    def _to_audit_decision(d: PipelineDecision) -> ExistingPolicyDecision:
        return ExistingPolicyDecision(
            category=PIICategory.PRIVATE_PERSON,
            action=_action_map.get(d.action, "allow"),
            reason=d.reason,
        )

    existing_decisions_inbound = [_to_audit_decision(d) for d in decisions[:1]]
    existing_decisions_outbound = [_to_audit_decision(d) for d in decisions[1:]]

    raw_query = request.scan_text or ""
    raw_output = output or ""

    record = AuditRecord(
        request_id=request.request_id,
        actor=actor,
        tool_name=request.tool_name,
        raw_query_hash=hashlib.sha256(raw_query.encode()).hexdigest(),
        inbound_detections=_safe_detections(inbound_detections or []),
        policy_decisions_inbound=existing_decisions_inbound,
        tool_input_after_policy=decisions[0].sanitized_text if decisions else raw_query,
        tool_output_raw_hash=hashlib.sha256(raw_output.encode()).hexdigest(),
        outbound_detections=_safe_detections(outbound_detections or []),
        policy_decisions_outbound=existing_decisions_outbound,
        tool_output_final=decisions[-1].sanitized_text if decisions and len(decisions) > 1 else raw_output,
        status=status,
        latency_ms=float(duration_ms),
        review_queue_id=next(
            (d.review_queue_id for d in decisions if d.review_queue_id), None
        ),
        policy_version=policy.version,
        model_version=get_model_version(),
    )

    _audit_logger.log(record)

    return PipelineLogEntry(
        request_id=request.request_id,
        timestamp=datetime.now(UTC),
        role=request.role,
        tool_name=request.tool_name,
        decisions=decisions,
        final_action=final_action,
        duration_ms=duration_ms,
        backend=backend,  # type: ignore[arg-type]
        status=status.value,
        error=error,
    )
