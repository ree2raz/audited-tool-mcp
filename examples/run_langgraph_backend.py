"""Example: run the LangGraph backend directly.

Demonstrates graph-native orchestration with the same 7-stage pipeline.
No Temporal cluster required. Set AUDITGUARD_BACKEND=langgraph in production.
"""
from __future__ import annotations

import asyncio
import uuid

from auditguard_mcp.config import get_config, set_config
from auditguard_mcp.pipeline.types import AuditRequest, AuditContext, PolicyMode
from auditguard_mcp.pipeline.langgraph_runner import run_audit_pipeline_langgraph
from auditguard_mcp.privacy import use_mock_detector


async def main():
    # Use mock PII detector for fast demo (no model download)
    use_mock_detector(True)

    set_config(get_config().model_copy(update={"backend": "langgraph"}))

    scenarios = [
        {
            "label": "Analyst -- clean query (expect: ALLOW)",
            "role": "analyst",
            "query": "SELECT id, first_name FROM customers LIMIT 5",
            "scan_text": "SELECT id, first_name FROM customers LIMIT 5",
        },
        {
            "label": "Intern -- blocked by RBAC (expect: RBAC_DENIED)",
            "role": "intern",
            "query": "SELECT * FROM customers",
            "scan_text": "SELECT * FROM customers",
        },
        {
            "label": "Analyst -- SSN in scan text (expect: BLOCK)",
            "role": "analyst",
            "query": "SELECT id FROM customers LIMIT 1",
            "scan_text": "My SSN is 123-45-6789",
        },
    ]

    for s in scenarios:
        print(f"\n{'─' * 60}")
        print(f"  {s['label']}")
        print(f"{'─' * 60}")

        request = AuditRequest(
            request_id=str(uuid.uuid4()),
            role=s["role"],  # type: ignore[arg-type]
            tool_name="sql_query",
            tool_input={"query": s["query"]},
            scan_text=s["scan_text"],
            requester="demo-user",
        )
        context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

        result = await run_audit_pipeline_langgraph(request, context)

        print(f"  backend      : {result.backend}")
        print(f"  status       : {result.status}")
        print(f"  final_action : {result.final_action.value}")
        print(f"  duration     : {result.duration_ms}ms")
        if result.error:
            print(f"  error        : {result.error}")
        for i, d in enumerate(result.decisions, 1):
            print(f"  decision[{i}]  : {d.action.value} — {d.reason}")


if __name__ == "__main__":
    asyncio.run(main())
