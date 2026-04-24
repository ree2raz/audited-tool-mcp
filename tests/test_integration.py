"""Integration tests — end-to-end pipeline through the MCP server internals.

Tests the full pipeline without actually running MCP transport:
  RBAC → PII scan → policy → tool dispatch → outbound scan → policy → audit

Uses mock PII detector for speed.
"""

from __future__ import annotations

import json
import os

import pytest

from audited_tool_mcp.audit import AuditLogger
from audited_tool_mcp.models import (
    Actor,
    AuditRecord,
    RequestStatus,
    Role,
)
from audited_tool_mcp.privacy import use_mock_detector
from audited_tool_mcp.server import _process_pipeline
from audited_tool_mcp.tools.sql_query import execute_sql


@pytest.fixture(autouse=True)
def _use_mock():
    """Always use mock PII detector in integration tests."""
    use_mock_detector(True)
    yield
    use_mock_detector(False)


@pytest.fixture
def audit_path(tmp_path, monkeypatch):
    """Use temp audit log."""
    path = str(tmp_path / "audit.jsonl")
    monkeypatch.setenv("AUDIT_LOG_PATH", path)
    # Also redirect vault and review queue
    monkeypatch.setenv("VAULT_PATH", str(tmp_path / "vault.jsonl"))
    monkeypatch.setenv("REVIEW_QUEUE_PATH", str(tmp_path / "review_queue.jsonl"))
    # Re-create audit logger with new path
    from audited_tool_mcp import server as server_module
    server_module.audit_logger = AuditLogger(path=path)
    return path


@pytest.fixture
def db_path():
    """Ensure the synthetic database exists, or create a temporary one for testing."""
    path = os.environ.get("DB_PATH", "data/synthetic_fs.sqlite")
    if not os.path.exists(path):
        import sys
        from scripts.seed_data import main as seed_main
        
        # Override DB_PATH for seed script if it was not set
        os.environ["DB_PATH"] = path
        
        print(f"\\nSeeding database at {path} for testing...")
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)
        seed_main()
    return path


class TestEndToEndPipeline:
    """Test the full pipeline end-to-end."""

    @pytest.mark.asyncio
    async def test_analyst_sql_query_success(self, audit_path, db_path):
        """Analyst executing a simple SQL query should succeed."""
        actor = Actor(role=Role.ANALYST, user_id="test-analyst")

        async def _execute(q: str) -> str:
            return execute_sql(q, role=actor.role)

        result = await _process_pipeline(
            actor=actor,
            tool_name="sql_query",
            query="SELECT id, first_name, last_name FROM customers LIMIT 5",
            tool_executor=_execute,
            sql_query="SELECT id, first_name, last_name FROM customers LIMIT 5",
        )

        # Should return valid JSON
        data = json.loads(result)
        assert isinstance(data, list) or isinstance(data, str)

        # Audit record should exist
        logger = AuditLogger(path=audit_path)
        records = logger.read_all()
        assert len(records) == 1
        assert records[0].tool_name == "sql_query"
        assert records[0].status in (RequestStatus.SUCCESS, RequestStatus.REVIEW_QUEUED)

    @pytest.mark.asyncio
    async def test_intern_rbac_denial(self, audit_path, db_path):
        """Intern should be denied access to all tools."""
        actor = Actor(role=Role.INTERN, user_id="test-intern")

        async def _execute(q: str) -> str:
            return execute_sql(q)

        result = await _process_pipeline(
            actor=actor,
            tool_name="sql_query",
            query="SELECT * FROM customers",
            tool_executor=_execute,
            sql_query="SELECT * FROM customers",
        )

        data = json.loads(result)
        assert "error" in data

        # Audit record should capture the denial
        logger = AuditLogger(path=audit_path)
        records = logger.read_all()
        assert len(records) == 1
        assert records[0].status == RequestStatus.RBAC_DENIED

    @pytest.mark.asyncio
    async def test_analyst_blocked_from_ssn(self, audit_path, db_path):
        """Analyst querying SSN column should be blocked by RBAC."""
        actor = Actor(role=Role.ANALYST, user_id="test-analyst")

        async def _execute(q: str) -> str:
            return execute_sql(q, role=actor.role)

        result = await _process_pipeline(
            actor=actor,
            tool_name="sql_query",
            query="SELECT ssn FROM customers",
            tool_executor=_execute,
            sql_query="SELECT ssn FROM customers",
        )

        data = json.loads(result)
        assert "error" in data

        # Should be RBAC denied
        logger = AuditLogger(path=audit_path)
        records = logger.read_all()
        assert len(records) == 1
        assert records[0].status == RequestStatus.RBAC_DENIED

    @pytest.mark.asyncio
    async def test_audit_record_completeness(self, audit_path, db_path):
        """Audit record should have all required fields after a successful request."""
        actor = Actor(role=Role.ANALYST, user_id="test-analyst")

        async def _execute(q: str) -> str:
            return execute_sql(q, role=actor.role)

        await _process_pipeline(
            actor=actor,
            tool_name="sql_query",
            query="SELECT id, first_name FROM customers LIMIT 3",
            tool_executor=_execute,
            sql_query="SELECT id, first_name FROM customers LIMIT 3",
        )

        logger = AuditLogger(path=audit_path)
        records = logger.read_all()
        assert len(records) == 1

        record = records[0]
        # Check all critical fields are populated
        assert record.request_id
        assert record.timestamp_utc
        assert record.actor.role == Role.ANALYST
        assert record.tool_name == "sql_query"
        assert record.raw_query_hash
        assert len(record.raw_query_hash) == 64  # SHA-256
        assert record.policy_version
        assert record.model_version == "openai/privacy-filter"
        assert record.latency_ms > 0

    @pytest.mark.asyncio
    async def test_compliance_officer_full_access(self, audit_path, db_path):
        """Compliance officer should have full access with PII redaction in output."""
        actor = Actor(role=Role.COMPLIANCE_OFFICER, user_id="test-co")

        async def _execute(q: str) -> str:
            return execute_sql(q, role=actor.role)

        result = await _process_pipeline(
            actor=actor,
            tool_name="sql_query",
            query="SELECT id, first_name, last_name FROM customers LIMIT 3",
            tool_executor=_execute,
            sql_query="SELECT id, first_name, last_name FROM customers LIMIT 3",
        )

        # Should succeed
        logger = AuditLogger(path=audit_path)
        records = logger.read_all()
        assert len(records) == 1
        assert records[0].status in (RequestStatus.SUCCESS, RequestStatus.REVIEW_QUEUED)
