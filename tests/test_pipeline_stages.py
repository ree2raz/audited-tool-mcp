"""Tests for pipeline stages — backend-agnostic pure functions.

Each stage is tested in isolation using mock PII detector.
"""
from __future__ import annotations

import pytest

from auditguard_mcp.models import (
    PIIDetection,
    PIICategory,
    RBACDenied,
    RequestStatus,
    Role,
)
from auditguard_mcp.pipeline.types import (
    AuditRequest,
    AuditContext,
    PipelineAction,
    PipelineDecision,
    PolicyMode,
)
from auditguard_mcp.pipeline.stages import (
    check_rbac,
    scan_inbound_pii,
    apply_inbound_policy,
    scan_outbound_pii,
    apply_outbound_policy,
    write_audit_log,
)
from auditguard_mcp.privacy import use_mock_detector


@pytest.fixture(autouse=True)
def _use_mock():
    use_mock_detector(True)
    yield
    use_mock_detector(False)


@pytest.fixture
def sample_request():
    return AuditRequest(
        request_id="test-req-001",
        role=Role.ANALYST,
        tool_name="sql_query",
        tool_input={"query": "SELECT id, first_name FROM customers LIMIT 3"},
        scan_text="SELECT id, first_name FROM customers LIMIT 3",
        requester="test-user",
    )


@pytest.fixture
def permissive_context():
    return AuditContext(policy_mode=PolicyMode.PERMISSIVE)


# ---------------------------------------------------------------------------
# Stage 1: RBAC
# ---------------------------------------------------------------------------


class TestCheckRBAC:
    def test_analyst_allowed_sql(self, sample_request, permissive_context):
        check_rbac(sample_request, permissive_context)
        # Should not raise

    def test_intern_denied(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-002",
            role=Role.INTERN,
            tool_name="sql_query",
            tool_input={"query": "SELECT * FROM customers"},
            scan_text="SELECT * FROM customers",
            requester="intern-user",
        )
        with pytest.raises(RBACDenied):
            check_rbac(request, permissive_context)

    def test_unknown_tool_denied(self, sample_request, permissive_context):
        request = sample_request.model_copy(update={"tool_name": "admin_tool"})
        with pytest.raises(RBACDenied):
            check_rbac(request, permissive_context)


# ---------------------------------------------------------------------------
# Stage 2: Inbound PII Scan
# ---------------------------------------------------------------------------


class TestScanInboundPII:
    def test_no_pii(self, sample_request, permissive_context):
        result = scan_inbound_pii(sample_request, permissive_context)
        assert result.has_pii is False
        assert result.confidence == 0.0

    def test_detects_email(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-003",
            role=Role.ANALYST,
            tool_name="sql_query",
            tool_input={"query": "SELECT * FROM customers WHERE email = 'alice@example.com'"},
            scan_text="SELECT * FROM customers WHERE email = 'alice@example.com'",
            requester="test-user",
        )
        result = scan_inbound_pii(request, permissive_context)
        assert result.has_pii is True
        assert "private_email" in result.detected_types

    def test_empty_text(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-004",
            role=Role.ANALYST,
            tool_name="sql_query",
            tool_input={},
            scan_text="",
            requester="test-user",
        )
        result = scan_inbound_pii(request, permissive_context)
        assert result.has_pii is False

    def test_respects_threshold(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-005",
            role=Role.ANALYST,
            tool_name="sql_query",
            tool_input={"query": "Contact john@example.com"},
            scan_text="Contact john@example.com",
            requester="test-user",
        )
        # High threshold should filter out detections
        high_threshold_ctx = permissive_context.model_copy(update={"pii_threshold": 0.99})
        result = scan_inbound_pii(request, high_threshold_ctx)
        assert result.has_pii is False  # mock returns 0.95 confidence


# ---------------------------------------------------------------------------
# Stage 3: Inbound Policy
# ---------------------------------------------------------------------------


class TestApplyInboundPolicy:
    def test_allow_clean_text(self, sample_request, permissive_context):
        pii_result = scan_inbound_pii(sample_request, permissive_context)
        decision = apply_inbound_policy(sample_request, pii_result, permissive_context)
        assert decision.action == PipelineAction.ALLOW

    def test_transform_on_email(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-006",
            role=Role.ANALYST,
            tool_name="sql_query",
            tool_input={"query": "SELECT * FROM customers WHERE email = 'alice@example.com'"},
            scan_text="SELECT * FROM customers WHERE email = 'alice@example.com'",
            requester="test-user",
        )
        pii_result = scan_inbound_pii(request, permissive_context)
        decision = apply_inbound_policy(request, pii_result, permissive_context)
        # Permissive analyst allows emails inbound → ALLOW
        assert decision.action == PipelineAction.ALLOW

    def test_block_on_secret(self, permissive_context):
        request = AuditRequest(
            request_id="test-req-007",
            role=Role.ANALYST,
            tool_name="sql_query",
            tool_input={"query": "SELECT * FROM secrets"},
            scan_text="My SSN is 123-45-6789",
            requester="test-user",
        )
        pii_result = scan_inbound_pii(request, permissive_context)
        # The mock detector detects SSN-like patterns as SECRET
        decision = apply_inbound_policy(request, pii_result, permissive_context)
        # Permissive analyst blocks secrets inbound
        assert decision.action == PipelineAction.BLOCK


# ---------------------------------------------------------------------------
# Stage 5: Outbound PII Scan
# ---------------------------------------------------------------------------


class TestScanOutboundPII:
    def test_no_pii_in_output(self, permissive_context):
        output = '[{"id": 1, "name": "Alice"}]'
        result = scan_outbound_pii(output, permissive_context)
        assert result.has_pii is False

    def test_detects_email_in_output(self, permissive_context):
        output = '[{"id": 1, "email": "alice@example.com"}]'
        result = scan_outbound_pii(output, permissive_context)
        assert result.has_pii is True
        assert "private_email" in result.detected_types


# ---------------------------------------------------------------------------
# Stage 6: Outbound Policy
# ---------------------------------------------------------------------------


class TestApplyOutboundPolicy:
    def test_redact_email_outbound(self, permissive_context):
        output = '[{"id": 1, "email": "alice@example.com"}]'
        pii_result = scan_outbound_pii(output, permissive_context)
        decision = apply_outbound_policy(output, pii_result, permissive_context)
        # Permissive analyst ALLOWS emails outbound (strict redacts them)
        assert decision.action == PipelineAction.ALLOW

    def test_allow_clean_output(self, permissive_context):
        output = '[{"id": 1, "name": "Alice"}]'
        pii_result = scan_outbound_pii(output, permissive_context)
        decision = apply_outbound_policy(output, pii_result, permissive_context)
        assert decision.action == PipelineAction.ALLOW


# ---------------------------------------------------------------------------
# Stage 7: Audit Log
# ---------------------------------------------------------------------------


class TestWriteAuditLog:
    def test_writes_log_entry(self, sample_request, permissive_context, tmp_path, monkeypatch):
        audit_path = str(tmp_path / "test_audit.jsonl")
        monkeypatch.setenv("AUDIT_LOG_PATH", audit_path)

        # Re-import to pick up new env var
        from auditguard_mcp.pipeline import stages
        stages._audit_logger = stages.AuditLogger(path=audit_path)

        decisions = [
            PipelineDecision(action=PipelineAction.ALLOW, reason="No PII detected")
        ]
        entry = write_audit_log(
            request=sample_request,
            output='[{"id": 1}]',
            decisions=decisions,
            context=permissive_context,
            duration_ms=42,
            backend="async",
        )

        assert entry.request_id == sample_request.request_id
        assert entry.backend == "async"
        assert entry.duration_ms == 42
        assert entry.final_action == PipelineAction.ALLOW

        # Verify file was written
        import json
        with open(audit_path) as f:
            line = f.readline().strip()
        data = json.loads(line)
        assert data["request_id"] == sample_request.request_id
        assert data["tool_name"] == "sql_query"
