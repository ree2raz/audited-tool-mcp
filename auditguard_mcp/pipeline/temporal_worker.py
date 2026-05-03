"""Temporal worker -- registers workflow + activities with the Temporal server.

Run this as a long-running process alongside your MCP server:
    python -m auditguard_mcp.pipeline.temporal_worker
"""
from __future__ import annotations

import asyncio
import os

from temporalio.client import Client
from temporalio.worker import Worker

from auditguard_mcp.config import get_config

# Pre-warm the model before starting the worker so the first activity
# invocation doesn't hit the 60-second timeout during model load.
from auditguard_mcp.privacy import detect as _privacy_detect  # noqa: E402

_prewarm_done = False

def _prewarm_model():
    global _prewarm_done
    if _prewarm_done:
        return
    print("Pre-warming Privacy Filter model (1.5B MoE, 50M active params)...")
    _privacy_detect("Warmup")
    print("Model loaded. Starting worker...")
    _prewarm_done = True


from .temporal_runner import (
    AuditPipelineWorkflow,
    check_rbac_activity,
    scan_inbound_pii_activity,
    apply_inbound_policy_activity,
    execute_bounded_activity,
    scan_outbound_pii_activity,
    apply_outbound_policy_activity,
    write_audit_log_activity,
)


async def run_worker(
    temporal_address: str | None = None,
    task_queue: str | None = None,
):
    """Start a Temporal worker listening on the configured task queue."""
    config = get_config()
    address = temporal_address or config.temporal_address
    queue = task_queue or config.temporal_task_queue

    client = await Client.connect(address)

    _prewarm_model()

    worker = Worker(
        client,
        task_queue=queue,
        workflows=[AuditPipelineWorkflow],
        activities=[
            check_rbac_activity,
            scan_inbound_pii_activity,
            apply_inbound_policy_activity,
            execute_bounded_activity,
            scan_outbound_pii_activity,
            apply_outbound_policy_activity,
            write_audit_log_activity,
        ],
    )

    print(f"Worker started, listening on task queue: {queue} at {address}")
    await worker.run()


def main():
    """CLI entrypoint for the Temporal worker."""
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
