"""Async backend -- the original implementation.

Fast, simple, no external dependencies.
Loses durability across process crashes.
"""
from __future__ import annotations

import asyncio
import json
import time

from auditguard_mcp.models import RBACDenied, RequestStatus

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
    PipelineAction,
    PipelineDecision,
    PipelineLogEntry,
)


async def run_audit_pipeline_async(
    request: AuditRequest,
    context: AuditContext,
) -> PipelineLogEntry:
    """Runs the 7-stage audit pipeline using asyncio.

    Failures are caught and logged but do not retry across process boundaries.

    Tradeoff vs Temporal:
      - Lower latency (~1-5ms overhead)
      - No external dependencies
      - If the worker dies mid-pipeline, the request is lost and audit log
        may be incomplete.
    """
    start = time.monotonic()
    decisions = []
    inbound_detections = None
    outbound_detections = None
    output: str | None = None
    status = RequestStatus.SUCCESS
    error_msg: str | None = None

    try:
        # Stage 1: RBAC (fail-fast)
        await asyncio.to_thread(check_rbac, request, context)

        # Stage 2: Inbound PII scan (CPU-bound -- run in thread)
        pii_inbound = await asyncio.to_thread(scan_inbound_pii, request, context)
        inbound_detections = [
            __import__("auditguard_mcp.models", fromlist=["PIIDetection"]).PIIDetection.model_validate(d)
            for d in pii_inbound.detections
        ]

        # Stage 3: Role-specific policy (inbound)
        inbound_decision = await asyncio.to_thread(
            apply_inbound_policy, request, pii_inbound, context
        )
        decisions.append(inbound_decision)

        if inbound_decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
            status = RequestStatus.BLOCKED
            duration_ms = int((time.monotonic() - start) * 1000)
            return write_audit_log(
                request, None, decisions, context, duration_ms, "async",
                inbound_detections=inbound_detections,
                status=status,
                error="Inbound policy denied or blocked the request",
            )

        if inbound_decision.action == PipelineAction.HUMAN_REVIEW:
            # In async backend, we don't wait for human review -- we audit-and-allow
            # Returning a log entry with review flag set.
            status = RequestStatus.REVIEW_QUEUED
            duration_ms = int((time.monotonic() - start) * 1000)
            return write_audit_log(
                request, None, decisions, context, duration_ms, "async",
                inbound_detections=inbound_detections,
                status=status,
                error="Human review required (async backend cannot wait)",
            )

        # Stage 4: Bounded execution
        output = await execute_bounded(request, inbound_decision, context)

        # Stage 5: Outbound PII scan
        pii_outbound = await asyncio.to_thread(scan_outbound_pii, output, context)
        outbound_detections = [
            __import__("auditguard_mcp.models", fromlist=["PIIDetection"]).PIIDetection.model_validate(d)
            for d in pii_outbound.detections
        ]

        # Stage 6: Outbound policy
        outbound_decision = await asyncio.to_thread(
            apply_outbound_policy, output, pii_outbound, context
        )
        decisions.append(outbound_decision)

        if outbound_decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
            status = RequestStatus.BLOCKED
            output = outbound_decision.sanitized_text

        # Stage 7: Audit log (always)
        duration_ms = int((time.monotonic() - start) * 1000)
        return write_audit_log(
            request, output, decisions, context, duration_ms, "async",
            inbound_detections=inbound_detections,
            outbound_detections=outbound_detections,
            status=status,
        )

    except RBACDenied as e:
        # RBAC is the fail-fast gate -- record it specifically so the
        # frontend can show "RBAC Gate: failed" instead of a generic error.
        duration_ms = int((time.monotonic() - start) * 1000)
        error_msg = str(e)
        status = RequestStatus.RBAC_DENIED
        decisions.append(
            PipelineDecision(
                action=PipelineAction.DENY,
                reason=error_msg,
                triggered_rules=["rbac"],
                sanitized_text=json.dumps({"error": error_msg}),
            )
        )
        return write_audit_log(
            request, output, decisions, context, duration_ms, "async",
            inbound_detections=inbound_detections,
            outbound_detections=outbound_detections,
            status=status,
            error=error_msg,
        )

    except Exception as e:
        # Best-effort audit log on failure -- but if the process dies,
        # this entry is lost. That's the durability gap Temporal closes.
        duration_ms = int((time.monotonic() - start) * 1000)
        error_msg = f"{type(e).__name__}: {e}"
        status = RequestStatus.ERROR
        return write_audit_log(
            request, output, decisions, context, duration_ms, "async",
            inbound_detections=inbound_detections,
            outbound_detections=outbound_detections,
            status=status,
            error=error_msg,
        )
