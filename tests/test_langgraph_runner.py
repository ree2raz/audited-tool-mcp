"""Tests for the LangGraph runner -- mirrors test_async_runner.py.

Same 7-stage pipeline, same assertions. Confirms semantic equivalence
between the langgraph and async backends.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("langgraph", reason="langgraph not installed")

from auditguard_mcp.models import RequestStatus, Role
from auditguard_mcp.pipeline.types import (
    AuditRequest,
    AuditContext,
    PipelineAction,
    PolicyMode,
)
from auditguard_mcp.pipeline.langgraph_runner import run_audit_pipeline_langgraph
from auditguard_mcp.privacy import use_mock_detector


@pytest.fixture(autouse=True)
def _use_mock():
    use_mock_detector(True)
    yield
    use_mock_detector(False)


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    """Temp SQLite database seeded with minimal data."""
    import sqlite3
    db = str(tmp_path / "test_db.sqlite")
    monkeypatch.setenv("DB_PATH", db)
    sqlite3.connect(db).close()
    import auditguard_mcp.tools.sql_query as sql_module
    sql_module._engine = None
    sql_module._DB_PATH = db
    from auditguard_mcp.tools.sql_query import _get_engine
    from sqlalchemy import text
    engine = _get_engine()
    with engine.connect() as conn:
        conn.execute(text(
            "CREATE TABLE IF NOT EXISTS customers "
            "(id INTEGER PRIMARY KEY, first_name TEXT, last_name TEXT)"
        ))
        conn.execute(text(
            "INSERT INTO customers (first_name, last_name) "
            "VALUES ('Alice', 'Smith'), ('Bob', 'Jones')"
        ))
        conn.commit()
    return db


@pytest.fixture
def audit_path(tmp_path, monkeypatch):
    path = str(tmp_path / "audit.jsonl")
    monkeypatch.setenv("AUDIT_LOG_PATH", path)
    from auditguard_mcp.pipeline import stages
    from auditguard_mcp.audit import AuditLogger
    stages._audit_logger = AuditLogger(path=path)
    return path


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_happy_path_sql_query(audit_path, db_path):
    request = AuditRequest(
        request_id="lg-happy-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id, first_name FROM customers LIMIT 2"},
        scan_text="SELECT id, first_name FROM customers LIMIT 2",
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.backend == "langgraph"
    assert result.status == RequestStatus.SUCCESS.value
    assert result.final_action == PipelineAction.ALLOW
    assert result.duration_ms > 0
    assert len(result.decisions) >= 1


# ---------------------------------------------------------------------------
# RBAC denial
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_intern_rbac_denial(audit_path):
    request = AuditRequest(
        request_id="lg-rbac-001",
        role=Role.INTERN,
        tool_name="sql_query",
        tool_input={"query": "SELECT * FROM customers"},
        scan_text="SELECT * FROM customers",
        requester="test-intern",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.backend == "langgraph"
    assert result.status == RequestStatus.RBAC_DENIED.value
    assert result.error is not None
    assert "RBAC" in result.error or "rbac" in result.error
    assert len(result.decisions) == 1
    assert result.decisions[0].action == PipelineAction.DENY


# ---------------------------------------------------------------------------
# Inbound block
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_blocked_by_inbound_policy(audit_path, db_path):
    request = AuditRequest(
        request_id="lg-block-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id, first_name FROM customers LIMIT 1"},
        scan_text="My SSN is 123-45-6789",  # triggers SECRET -> BLOCK
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.backend == "langgraph"
    assert result.final_action in (PipelineAction.BLOCK, PipelineAction.DENY)


# ---------------------------------------------------------------------------
# Outbound transform -- PII redacted in tool output
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_outbound_transform(audit_path, db_path, monkeypatch):
    """Injects a mock tool that returns PII so outbound policy runs."""
    import auditguard_mcp.pipeline.langgraph_runner as lg
    from auditguard_mcp.tools import registry as reg

    async def _pii_tool(tool_input, role):
        return "Customer email: alice@example.com, SSN: 123-45-6789"

    # Bypass RBAC so the custom tool name is allowed
    monkeypatch.setattr(lg, "check_rbac", lambda request, context: None)

    original = dict(reg.TOOL_REGISTRY)
    reg.TOOL_REGISTRY["pii_tool"] = _pii_tool
    try:
        request = AuditRequest(
            request_id="lg-out-001",
            role=Role.ANALYST,
            tool_name="pii_tool",
            tool_input={},
            scan_text="",
            requester="test-analyst",
        )
        context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)
        result = await run_audit_pipeline_langgraph(request, context)
        assert result.backend == "langgraph"
        # Two decisions: inbound + outbound
        assert len(result.decisions) == 2
    finally:
        reg.TOOL_REGISTRY.clear()
        reg.TOOL_REGISTRY.update(original)


# ---------------------------------------------------------------------------
# Human-review short-circuit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_human_review_short_circuit(audit_path, monkeypatch):
    """HUMAN_REVIEW inbound action causes immediate short-circuit (no execution)."""
    import auditguard_mcp.pipeline.langgraph_runner as lg
    from auditguard_mcp.pipeline.types import PipelineDecision, PipelineAction

    def _force_review(request, pii_result, context):
        return PipelineDecision(
            action=PipelineAction.HUMAN_REVIEW,
            reason="Forced review for test",
            triggered_rules=["test"],
        )

    # Patch the runner's local binding (imported at module load, not stages attribute)
    monkeypatch.setattr(lg, "apply_inbound_policy", _force_review)

    request = AuditRequest(
        request_id="lg-review-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id FROM customers LIMIT 1"},
        scan_text="",
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.backend == "langgraph"
    assert result.status == RequestStatus.REVIEW_QUEUED.value
    assert result.final_action == PipelineAction.HUMAN_REVIEW


# ---------------------------------------------------------------------------
# Audit record completeness
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_record_fields(audit_path, db_path):
    request = AuditRequest(
        request_id="lg-audit-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id FROM customers LIMIT 1"},
        scan_text="SELECT id FROM customers LIMIT 1",
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.request_id == "lg-audit-001"
    assert result.role == Role.ANALYST
    assert result.tool_name == "sql_query"
    assert result.timestamp is not None

    with open(audit_path) as f:
        data = json.loads(f.readline().strip())
    assert data["request_id"] == "lg-audit-001"
    assert data["actor"]["role"] == "analyst"


# ---------------------------------------------------------------------------
# Partial-state preservation on mid-pipeline error
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_error_preserves_partial_state(audit_path, monkeypatch):
    """If execution fails after inbound scan, the audit log still carries
    the inbound decision -- not an empty decisions list."""
    import auditguard_mcp.pipeline.langgraph_runner as lg

    async def _boom(request, decision, context):
        raise RuntimeError("simulated tool crash")

    # Patch the runner's local binding (imported at module load, not stages attribute)
    monkeypatch.setattr(lg, "execute_bounded", _boom)

    request = AuditRequest(
        request_id="lg-error-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id FROM customers LIMIT 1"},
        scan_text="",
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    result = await run_audit_pipeline_langgraph(request, context)

    assert result.backend == "langgraph"
    assert result.status == RequestStatus.ERROR.value
    # Inbound policy decision must be preserved despite the crash
    assert len(result.decisions) >= 1, "partial decisions lost on error"


# ---------------------------------------------------------------------------
# Server dispatch: blocked content must never reach the MCP client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_blocked_content_not_leaked(audit_path, monkeypatch):
    """_run_pipeline_v2 with langgraph backend must return error JSON, not the
    original blocked text, when an inbound BLOCK is triggered by sensitive content."""
    from auditguard_mcp.config import AuditConfig, set_config
    from auditguard_mcp.server import _run_pipeline_v2

    set_config(AuditConfig(backend="langgraph"))
    monkeypatch.setattr(
        "auditguard_mcp.server._extract_output.__module__",
        "auditguard_mcp.server",
        raising=False,
    )

    secret = "123-45-6789"
    request = AuditRequest(
        request_id="lg-dispatch-block-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id FROM customers LIMIT 1"},
        scan_text=f"My SSN is {secret}",
        requester="test-analyst",
    )
    context = AuditContext(policy_mode=PolicyMode.PERMISSIVE)

    output, meta = await _run_pipeline_v2(request, context)

    assert meta["backend"] == "langgraph"
    # The raw SSN must never appear in the returned output
    assert secret not in output, f"blocked content leaked to MCP client: {output!r}"
    # Output must be error JSON, not empty string
    parsed = json.loads(output)
    assert "error" in parsed
