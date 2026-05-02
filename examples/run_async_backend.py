"""Example: run the async backend directly.

This demonstrates the low-latency, single-process path.
No external dependencies required.
"""
from __future__ import annotations

import asyncio
import uuid

from auditguard_mcp.config import get_config, set_config
from auditguard_mcp.pipeline.types import AuditRequest, AuditContext, PolicyMode
from auditguard_mcp.pipeline.async_runner import run_audit_pipeline_async
from auditguard_mcp.privacy import use_mock_detector


async def main():
    # Use mock PII detector for fast demo (no model download)
    use_mock_detector(True)

    # Ensure we're using the async backend
    set_config(get_config().model_copy(update={"backend": "async"}))

    request = AuditRequest(
        request_id=str(uuid.uuid4()),
        role="analyst",  # type: ignore[arg-type]
        tool_name="sql_query",
        tool_input={"query": "SELECT id, first_name, last_name FROM customers LIMIT 5"},
        scan_text="SELECT id, first_name, last_name FROM customers LIMIT 5",
        requester="demo-user",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    print(f"Running async pipeline for request {request.request_id}...")
    result = await run_audit_pipeline_async(request, context)

    print(f"\nFinal action: {result.final_action}")
    print(f"Duration: {result.duration_ms}ms")
    print(f"Status: {result.status}")
    print(f"Decisions: {len(result.decisions)}")
    for d in result.decisions:
        print(f"  - {d.action.value}: {d.reason}")


if __name__ == "__main__":
    asyncio.run(main())
