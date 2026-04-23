"""Tests for the audit logger (audited_tool_mcp.audit)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from audited_tool_mcp.audit import AuditLogger
from audited_tool_mcp.models import (
    Actor,
    AuditRecord,
    PIICategory,
    PIIDetection,
    PolicyAction,
    PolicyDecision,
    RequestStatus,
    Role,
)


@pytest.fixture
def audit_logger(tmp_path):
    """Create an audit logger writing to a temp directory."""
    path = str(tmp_path / "test_audit.jsonl")
    return AuditLogger(path=path)


@pytest.fixture
def sample_record():
    """Create a sample audit record."""
    return AuditRecord(
        request_id="test-req-001",
        actor=Actor(role=Role.ANALYST, user_id="test-user", session_id="test-session"),
        tool_name="sql_query",
        raw_query_hash="abc123def456",
        inbound_detections=[
            PIIDetection(
                category=PIICategory.PRIVATE_PERSON,
                start=11, end=22, text="[private_person]", confidence=0.95,
            )
        ],
        policy_decisions_inbound=[
            PolicyDecision(
                category=PIICategory.PRIVATE_PERSON,
                action=PolicyAction.ALLOW,
                reason="Names allowed for analyst lookups",
            )
        ],
        tool_input_after_policy="SELECT * FROM customers WHERE name = 'Alice'",
        tool_output_raw_hash="xyz789",
        outbound_detections=[],
        policy_decisions_outbound=[],
        tool_output_final='[{"id": 1, "name": "[private_person]"}]',
        status=RequestStatus.SUCCESS,
        latency_ms=42.5,
        policy_version="permissive_analyst_v1",
        model_version="openai/privacy-filter",
    )


class TestAuditLogger:
    def test_log_creates_file(self, audit_logger, sample_record):
        audit_logger.log(sample_record)
        assert Path(audit_logger.path).exists()

    def test_log_writes_valid_json(self, audit_logger, sample_record):
        audit_logger.log(sample_record)

        with open(audit_logger.path) as f:
            line = f.readline().strip()

        data = json.loads(line)
        assert data["request_id"] == "test-req-001"
        assert data["tool_name"] == "sql_query"

    def test_log_appends_multiple_records(self, audit_logger, sample_record):
        audit_logger.log(sample_record)
        audit_logger.log(sample_record)

        with open(audit_logger.path) as f:
            lines = [l.strip() for l in f if l.strip()]

        assert len(lines) == 2

    def test_read_all(self, audit_logger, sample_record):
        audit_logger.log(sample_record)
        audit_logger.log(sample_record)

        records = audit_logger.read_all()
        assert len(records) == 2
        assert all(isinstance(r, AuditRecord) for r in records)

    def test_read_all_empty_file(self, audit_logger):
        records = audit_logger.read_all()
        assert records == []

    def test_clear(self, audit_logger, sample_record):
        audit_logger.log(sample_record)
        assert Path(audit_logger.path).exists()

        audit_logger.clear()
        assert not Path(audit_logger.path).exists()

    def test_all_fields_present(self, audit_logger, sample_record):
        """Every field in the AuditRecord schema should be present in the JSON."""
        audit_logger.log(sample_record)

        with open(audit_logger.path) as f:
            data = json.loads(f.readline())

        expected_fields = {
            "request_id", "timestamp_utc", "actor", "tool_name",
            "raw_query_hash", "inbound_detections", "policy_decisions_inbound",
            "tool_input_after_policy", "tool_output_raw_hash",
            "outbound_detections", "policy_decisions_outbound",
            "tool_output_final", "status", "latency_ms",
            "review_queue_id", "policy_version", "model_version",
        }
        assert expected_fields.issubset(set(data.keys()))

    def test_no_raw_pii_in_detections(self, audit_logger):
        """Audit records should not contain raw PII — only category placeholders."""
        record = AuditRecord(
            actor=Actor(role=Role.ANALYST, user_id="u1"),
            tool_name="sql_query",
            raw_query_hash="hash123",
            inbound_detections=[
                PIIDetection(
                    category=PIICategory.PRIVATE_PERSON,
                    start=0, end=10,
                    text="[private_person]",  # Placeholder, not real name
                    confidence=0.95,
                ),
            ],
            policy_decisions_inbound=[],
            tool_input_after_policy="sanitized query",
            policy_version="test_v1",
            model_version="openai/privacy-filter",
        )
        audit_logger.log(record)

        with open(audit_logger.path) as f:
            line = f.readline()

        # The text field should be a category placeholder, not a real name
        data = json.loads(line)
        for det in data["inbound_detections"]:
            assert det["text"].startswith("[")
            assert det["text"].endswith("]")

    def test_policy_and_model_version_present(self, audit_logger, sample_record):
        """policy_version and model_version must be in every audit record."""
        audit_logger.log(sample_record)

        with open(audit_logger.path) as f:
            data = json.loads(f.readline())

        assert data["policy_version"] == "permissive_analyst_v1"
        assert data["model_version"] == "openai/privacy-filter"
