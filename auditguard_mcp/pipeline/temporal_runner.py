"""Temporal backend -- durable execution of the 7-stage audit pipeline.

Why Temporal:
- Each stage is an activity with independent retry policy
- Pipeline state survives worker crashes (resumes from last completed activity)
- Long-running stages (human review) supported via signals
- Full event history for debugging and audit
- Heartbeating for long-running stages catches stuck workers

Tradeoffs vs. async backend:
- Higher latency overhead (~50-100ms per activity for serialization + scheduling)
- Operational complexity (Temporal cluster required)
- Worth it when: stages can fail independently, durability matters,
  human-in-the-loop is needed
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from temporalio import workflow, activity
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError

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
# Activities -- wrap stage functions for Temporal execution
# ============================================================================

@activity.defn(name="check_rbac")
async def check_rbac_activity(
    request: AuditRequest, context: AuditContext
) -> None:
    """RBAC is fast and deterministic. Tight retry, short timeout."""
    check_rbac(request, context)


@activity.defn(name="scan_inbound_pii")
async def scan_inbound_pii_activity(
    request: AuditRequest, context: AuditContext
) -> PIIScanResult:
    """PII scan via 1.5B model -- slowest stage.

    Heartbeating ensures Temporal knows we're alive on long inputs.
    """
    activity.heartbeat("starting PII scan")
    result = scan_inbound_pii(request, context)
    activity.heartbeat("PII scan complete")
    return result


@activity.defn(name="apply_inbound_policy")
async def apply_inbound_policy_activity(
    request: AuditRequest,
    pii_result: PIIScanResult,
    context: AuditContext,
) -> PipelineDecision:
    """Applies role-specific inbound policy."""
    return apply_inbound_policy(request, pii_result, context)


@activity.defn(name="execute_bounded")
async def execute_bounded_activity(
    request: AuditRequest,
    decision: PipelineDecision,
    context: AuditContext,
) -> dict[str, str]:
    """The actual tool call. Wrap output in dict for serialization.

    Activity timeout enforces bounded execution.
    """
    output = await execute_bounded(request, decision, context)
    return {"output": output}


@activity.defn(name="scan_outbound_pii")
async def scan_outbound_pii_activity(
    output: dict[str, str], context: AuditContext
) -> PIIScanResult:
    """Scans tool output for outbound PII."""
    return scan_outbound_pii(output["output"], context)


@activity.defn(name="apply_outbound_policy")
async def apply_outbound_policy_activity(
    output: dict[str, str],
    pii_result: PIIScanResult,
    context: AuditContext,
) -> PipelineDecision:
    """Applies outbound policy to tool output."""
    return apply_outbound_policy(output["output"], pii_result, context)


@activity.defn(name="write_audit_log")
async def write_audit_log_activity(
    request: AuditRequest,
    output: dict[str, str] | None,
    decisions: list[PipelineDecision],
    context: AuditContext,
    duration_ms: int,
    inbound_detections: list[dict[str, Any]] | None = None,
    outbound_detections: list[dict[str, Any]] | None = None,
    status: str = "success",
    error: str | None = None,
) -> PipelineLogEntry:
    """Audit log write -- must be reliable.

    Long retry policy because durability of audit trail is critical.
    """
    output_value = output["output"] if output else None
    inbound_dets = [PIIDetection.model_validate(d) for d in (inbound_detections or [])]
    outbound_dets = [PIIDetection.model_validate(d) for d in (outbound_detections or [])]
    return write_audit_log(
        request,
        output_value,
        decisions,
        context,
        duration_ms,
        "temporal",
        inbound_detections=inbound_dets,
        outbound_detections=outbound_dets,
        status=RequestStatus(status),
        error=error,
    )


# ============================================================================
# Retry policies
# ============================================================================

RBAC_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=5),
    maximum_attempts=3,
    non_retryable_error_types=["RBACDenied"],
)

PII_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=5,
    backoff_coefficient=2.0,
)

EXECUTION_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=2,  # most tool calls shouldn't auto-retry blindly
    non_retryable_error_types=["ValueError", "ApplicationError"],
)

AUDIT_LOG_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(minutes=5),
    maximum_attempts=20,  # never give up on audit log
)


# ============================================================================
# Workflow -- orchestrates the 7 stages
# ============================================================================

@workflow.defn(name="AuditPipelineWorkflow", sandboxed=False)
class AuditPipelineWorkflow:
    """Temporal workflow for the 7-stage audit pipeline.

    Workflow code must be deterministic -- no random, no real time, no IO.
    All non-deterministic work happens in activities.
    """

    def __init__(self):
        self._human_review_decision: PipelineDecision | None = None
        self._cancelled = False

    @workflow.signal(name="human_review_complete")
    async def human_review_complete(self, decision: PipelineDecision):
        """Signal sent when a human reviewer approves/denies a flagged request.

        This is what makes "human-in-the-loop" durable.
        """
        self._human_review_decision = decision

    @workflow.signal(name="cancel")
    async def cancel(self):
        self._cancelled = True

    @workflow.run
    async def run(
        self,
        request: AuditRequest,
        context: AuditContext,
    ) -> PipelineLogEntry:
        decisions: list[PipelineDecision] = []
        output: dict[str, str] | None = None
        inbound_detections: list[dict[str, Any]] | None = None
        outbound_detections: list[dict[str, Any]] | None = None
        start_time = workflow.now()
        status = "success"
        error_msg: str | None = None

        try:
            # Stage 1: RBAC (fail-fast)
            await workflow.execute_activity(
                check_rbac_activity,
                args=[request, context],
                start_to_close_timeout=timedelta(seconds=5),
                retry_policy=RBAC_RETRY,
            )

            # Stage 2: Inbound PII scan
            pii_inbound: PIIScanResult = await workflow.execute_activity(
                scan_inbound_pii_activity,
                args=[request, context],
                start_to_close_timeout=timedelta(seconds=60),
                heartbeat_timeout=timedelta(seconds=10),
                retry_policy=PII_RETRY,
            )
            inbound_detections = pii_inbound.detections

            # Stage 3: Role-specific policy (inbound)
            inbound_decision: PipelineDecision = await workflow.execute_activity(
                apply_inbound_policy_activity,
                args=[request, pii_inbound, context],
                start_to_close_timeout=timedelta(seconds=5),
            )
            decisions.append(inbound_decision)

            # Branch: human-in-the-loop if policy says so
            if inbound_decision.action == PipelineAction.HUMAN_REVIEW:
                await workflow.wait_condition(
                    lambda: self._human_review_decision is not None or self._cancelled,
                    timeout=timedelta(hours=24),
                )
                if self._cancelled or self._human_review_decision is None:
                    raise ApplicationError("Request cancelled or human review timeout")
                decisions.append(self._human_review_decision)
                inbound_decision = self._human_review_decision

            # Branch: deny path
            if inbound_decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
                status = "blocked"
                duration = int((workflow.now() - start_time).total_seconds() * 1000)
                return await workflow.execute_activity(
                    write_audit_log_activity,
                    args=[
                        request,
                        None,
                        decisions,
                        context,
                        duration,
                        inbound_detections,
                        None,
                        status,
                        "Inbound policy denied or blocked",
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=AUDIT_LOG_RETRY,
                )

            # Stage 4: Bounded execution
            output = await workflow.execute_activity(
                execute_bounded_activity,
                args=[request, inbound_decision, context],
                start_to_close_timeout=timedelta(seconds=context.timeout_seconds),
                retry_policy=EXECUTION_RETRY,
            )

            # Stage 5: Outbound PII scan
            pii_outbound = await workflow.execute_activity(
                scan_outbound_pii_activity,
                args=[output, context],
                start_to_close_timeout=timedelta(seconds=60),
                heartbeat_timeout=timedelta(seconds=10),
                retry_policy=PII_RETRY,
            )
            outbound_detections = pii_outbound.detections

            # Stage 6: Outbound policy
            outbound_decision = await workflow.execute_activity(
                apply_outbound_policy_activity,
                args=[output, pii_outbound, context],
                start_to_close_timeout=timedelta(seconds=5),
            )
            decisions.append(outbound_decision)

            if outbound_decision.action in (PipelineAction.DENY, PipelineAction.BLOCK):
                status = "blocked"
                output = {"output": outbound_decision.sanitized_text}

            # Stage 7: Audit log (always -- never skip)
            duration = int((workflow.now() - start_time).total_seconds() * 1000)
            return await workflow.execute_activity(
                write_audit_log_activity,
                args=[
                    request,
                    output,
                    decisions,
                    context,
                    duration,
                    inbound_detections,
                    outbound_detections,
                    status,
                    error_msg,
                ],
                start_to_close_timeout=timedelta(seconds=10),
                retry_policy=AUDIT_LOG_RETRY,
            )

        except ActivityError as e:
            # Activity failures cross the boundary as ActivityError.
            # Unwrap to detect RBAC denial specifically.
            cause = e.cause
            is_rbac = False
            error_msg = str(e)
            while cause is not None:
                if (
                    isinstance(cause, ApplicationError)
                    and getattr(cause, "type", None) == "RBACDenied"
                ):
                    is_rbac = True
                    error_msg = str(cause)
                    break
                cause = getattr(cause, "cause", None)

            if is_rbac:
                duration = int(
                    (workflow.now() - start_time).total_seconds() * 1000
                )
                status = "rbac_denied"
                decisions.append(
                    PipelineDecision(
                        action=PipelineAction.DENY,
                        reason=error_msg,
                        triggered_rules=["rbac"],
                        sanitized_text=f'{{"error": "{error_msg}"}}',
                    )
                )
                return await workflow.execute_activity(
                    write_audit_log_activity,
                    args=[
                        request,
                        None,
                        decisions,
                        context,
                        duration,
                        inbound_detections,
                        None,
                        status,
                        error_msg,
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=AUDIT_LOG_RETRY,
                )
            # Not RBAC -- re-raise as ApplicationError so the workflow fails
            raise ApplicationError(f"Pipeline failed: {error_msg}")

        except ApplicationError:
            raise
        except Exception as e:
            # Catch-all: write audit log and re-raise as ApplicationError
            # so Temporal marks the workflow as failed (not stuck retrying)
            duration = int((workflow.now() - start_time).total_seconds() * 1000)
            status = "error"
            error_msg = f"{type(e).__name__}: {e}"
            try:
                await workflow.execute_activity(
                    write_audit_log_activity,
                    args=[
                        request,
                        output,
                        decisions,
                        context,
                        duration,
                        inbound_detections,
                        outbound_detections,
                        status,
                        error_msg,
                    ],
                    start_to_close_timeout=timedelta(seconds=10),
                    retry_policy=AUDIT_LOG_RETRY,
                )
            except Exception:
                pass  # Best effort -- if audit log fails, we still want to fail the workflow
            raise ApplicationError(f"Pipeline failed: {error_msg}")
