"""Example: run the Temporal backend.

Requires:
  1. Temporal cluster running (docker compose -f docker/docker-compose.temporal.yml up -d)
  2. Temporal worker running (python -m auditguard_mcp.pipeline.temporal_worker)
  3. temporalio installed (pip install auditguard-mcp[temporal])
"""
from __future__ import annotations

import asyncio
import uuid

from temporalio.client import Client

from auditguard_mcp.config import get_config, set_config
from auditguard_mcp.pipeline.types import AuditRequest, AuditContext, PolicyMode
from auditguard_mcp.pipeline.temporal_runner import AuditPipelineWorkflow
from auditguard_mcp.privacy import use_mock_detector


async def main():
    # Use mock PII detector for fast demo
    use_mock_detector(True)

    # Ensure we're using the temporal backend
    set_config(get_config().model_copy(update={"backend": "temporal"}))

    config = get_config()
    client = await Client.connect(config.temporal_address)

    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role="analyst",  # type: ignore[arg-type]
        tool_name="sql_query",
        tool_input={"query": "SELECT id, first_name, last_name FROM customers LIMIT 5"},
        scan_text="SELECT id, first_name, last_name FROM customers LIMIT 5",
        requester="demo-user",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    print(f"Starting Temporal workflow for request {request.request_id}...")
    handle = await client.start_workflow(
        AuditPipelineWorkflow.run,
        args=[request, context],
        id=f"audit-{request.request_id}",
        task_queue=config.temporal_task_queue,
    )

    print(f"Workflow ID: {handle.id}")
    print("Waiting for result...")

    result = await handle.result()

    print(f"\nFinal action: {result.final_action}")
    print(f"Duration: {result.duration_ms}ms")
    print(f"Status: {result.status}")
    print(f"Backend: {result.backend}")
    print(f"Decisions: {len(result.decisions)}")
    for d in result.decisions:
        print(f"  - {d.action.value}: {d.reason}")

    print(f"\nView workflow at: http://localhost:8080/namespaces/default/workflows/{handle.id}")


if __name__ == "__main__":
    asyncio.run(main())
