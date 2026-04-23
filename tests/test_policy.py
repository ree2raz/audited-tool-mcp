"""Tests for the policy engine (audited_tool_mcp.policy).

Tests all 6 actions: ALLOW, REDACT, HASH, VAULT, REVIEW, BLOCK.
Validates SanitizedInput structure, mutation records, and file outputs.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from audited_tool_mcp.models import (
    Actor,
    CategoryPolicy,
    Direction,
    PIICategory,
    PIIDetection,
    PolicyAction,
    PolicyConfig,
    PolicyViolation,
    Role,
)
from audited_tool_mcp.policy import (
    PERMISSIVE_ANALYST,
    STRICT_FINANCIAL,
    apply_policy,
    get_policy,
)
from audited_tool_mcp import policy as policy_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_detections():
    """Sample PII detections for testing."""
    return [
        PIIDetection(
            category=PIICategory.PRIVATE_PERSON,
            start=11,
            end=22,
            text="Alice Smith",
            confidence=0.95,
        ),
        PIIDetection(
            category=PIICategory.PRIVATE_EMAIL,
            start=36,
            end=55,
            text="alice@example.com",
            confidence=0.98,
        ),
    ]


@pytest.fixture
def sample_text():
    return "My name is Alice Smith, email is alice@example.com, thanks"


@pytest.fixture
def _temp_vault(tmp_path, monkeypatch):
    """Use a temp directory for vault and review queue files."""
    vault_path = str(tmp_path / "vault.jsonl")
    review_path = str(tmp_path / "review_queue.jsonl")
    monkeypatch.setattr(policy_module, "_VAULT_PATH", vault_path)
    monkeypatch.setattr(policy_module, "_REVIEW_QUEUE_PATH", review_path)
    return tmp_path


# ---------------------------------------------------------------------------
# Test each action
# ---------------------------------------------------------------------------


class TestPolicyActions:
    """Test each of the 6 policy actions individually."""

    def _make_policy(self, action: PolicyAction, direction: Direction = Direction.INBOUND) -> PolicyConfig:
        """Create a policy with the given action for all categories."""
        cats = {
            cat: CategoryPolicy(action=action, reason=f"Test {action.value}")
            for cat in PIICategory
        }
        return PolicyConfig(
            version=f"test_{action.value}_v1",
            inbound=cats if direction == Direction.INBOUND else {},
            outbound=cats if direction == Direction.OUTBOUND else {},
        )

    def test_allow(self, sample_text, sample_detections):
        policy = self._make_policy(PolicyAction.ALLOW)
        result = apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)

        assert result.mutated_text == sample_text  # No changes
        assert len(result.mutations) == 0
        assert len(result.decisions) == 2
        assert all(d.action == PolicyAction.ALLOW for d in result.decisions)
        assert not result.has_review_flag

    def test_redact(self, sample_text, sample_detections):
        policy = self._make_policy(PolicyAction.REDACT)
        result = apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)

        assert "[private_person]" in result.mutated_text
        assert "[private_email]" in result.mutated_text
        assert "Alice Smith" not in result.mutated_text
        assert "alice@example.com" not in result.mutated_text
        assert len(result.mutations) == 2
        assert all(m.action == PolicyAction.REDACT for m in result.mutations)

    def test_hash(self, sample_text, sample_detections):
        policy = self._make_policy(PolicyAction.HASH)
        result = apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)

        # Hash format: [category:sha256-first-8]
        assert "[private_person:" in result.mutated_text
        assert "[private_email:" in result.mutated_text
        assert "Alice Smith" not in result.mutated_text
        assert len(result.mutations) == 2
        assert all(m.action == PolicyAction.HASH for m in result.mutations)

        # Same input should produce same hash (deterministic)
        result2 = apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)
        assert result.mutated_text == result2.mutated_text

    def test_vault(self, sample_text, sample_detections, _temp_vault, tmp_path):
        policy = self._make_policy(PolicyAction.VAULT)
        result = apply_policy(
            sample_text, sample_detections, policy, Direction.INBOUND,
            request_id="test-req-123"
        )

        # Check replacement format
        assert "[private_person:vault-ref-" in result.mutated_text
        assert "[private_email:vault-ref-" in result.mutated_text
        assert len(result.mutations) == 2
        assert all(m.action == PolicyAction.VAULT for m in result.mutations)
        assert all(m.vault_ref is not None for m in result.mutations)

        # Check vault file was written
        vault_file = tmp_path / "vault.jsonl"
        assert vault_file.exists()
        lines = vault_file.read_text().strip().split("\n")
        assert len(lines) == 2  # Two vault entries

        # Verify vault entry structure
        entry = json.loads(lines[0])
        assert "vault_ref" in entry
        assert "original_text" in entry
        assert entry["request_id"] == "test-req-123"

    def test_review(self, sample_text, sample_detections, _temp_vault, tmp_path):
        actor = Actor(role=Role.ANALYST, user_id="test-user")
        policy = self._make_policy(PolicyAction.REVIEW)
        result = apply_policy(
            sample_text, sample_detections, policy, Direction.INBOUND,
            request_id="test-req-456", actor=actor, tool_name="sql_query"
        )

        # REVIEW leaves text intact
        assert result.mutated_text == sample_text
        assert len(result.mutations) == 0
        assert result.has_review_flag is True
        assert result.review_queue_id is not None

        # Check review queue file was written
        review_file = tmp_path / "review_queue.jsonl"
        assert review_file.exists()
        lines = review_file.read_text().strip().split("\n")
        assert len(lines) >= 1

    def test_block(self, sample_text, sample_detections):
        policy = self._make_policy(PolicyAction.BLOCK)

        with pytest.raises(PolicyViolation) as exc_info:
            apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)

        assert "BLOCK" in str(exc_info.value)

    def test_mixed_actions(self, sample_text, _temp_vault):
        """Test a policy with different actions for different categories."""
        policy = PolicyConfig(
            version="test_mixed_v1",
            inbound={
                PIICategory.PRIVATE_PERSON: CategoryPolicy(
                    action=PolicyAction.REDACT, reason="Redact names"
                ),
                PIICategory.PRIVATE_EMAIL: CategoryPolicy(
                    action=PolicyAction.HASH, reason="Hash emails"
                ),
            },
            outbound={},
        )

        detections = [
            PIIDetection(
                category=PIICategory.PRIVATE_PERSON,
                start=11, end=22, text="Alice Smith", confidence=0.95,
            ),
            PIIDetection(
                category=PIICategory.PRIVATE_EMAIL,
                start=36, end=53, text="alice@example.com", confidence=0.98,
            ),
        ]

        result = apply_policy(sample_text, detections, policy, Direction.INBOUND)

        assert "[private_person]" in result.mutated_text
        assert "[private_email:" in result.mutated_text  # Hash format
        assert len(result.decisions) == 2


# ---------------------------------------------------------------------------
# Test bundled policies
# ---------------------------------------------------------------------------


class TestBundledPolicies:
    """Test the two bundled policy configurations."""

    def test_strict_financial_exists(self):
        policy = get_policy("strict_financial")
        assert policy.version == "strict_financial_v1"
        assert len(policy.inbound) == 8
        assert len(policy.outbound) == 8

    def test_permissive_analyst_exists(self):
        policy = get_policy("permissive_analyst")
        assert policy.version == "permissive_analyst_v1"
        assert len(policy.inbound) == 8
        assert len(policy.outbound) == 8

    def test_unknown_policy_raises(self):
        with pytest.raises(ValueError, match="Unknown policy"):
            get_policy("nonexistent")

    def test_strict_blocks_secrets_inbound(self):
        """STRICT_FINANCIAL blocks secrets in inbound."""
        assert STRICT_FINANCIAL.inbound[PIICategory.SECRET].action == PolicyAction.BLOCK

    def test_strict_redacts_all_outbound_except_dates(self):
        """STRICT_FINANCIAL redacts most PII in outbound."""
        for cat in [PIICategory.PRIVATE_PERSON, PIICategory.PRIVATE_EMAIL,
                     PIICategory.PRIVATE_PHONE, PIICategory.PRIVATE_ADDRESS]:
            assert STRICT_FINANCIAL.outbound[cat].action == PolicyAction.REDACT

    def test_permissive_allows_emails_outbound(self):
        """PERMISSIVE_ANALYST allows emails in outbound for analysts."""
        assert PERMISSIVE_ANALYST.outbound[PIICategory.PRIVATE_EMAIL].action == PolicyAction.ALLOW


# ---------------------------------------------------------------------------
# Test SanitizedInput structure
# ---------------------------------------------------------------------------


class TestSanitizedInputStructure:
    def test_original_hash_is_sha256(self, sample_text, sample_detections):
        policy = PolicyConfig(
            version="test_v1",
            inbound={
                cat: CategoryPolicy(action=PolicyAction.ALLOW, reason="test")
                for cat in PIICategory
            },
            outbound={},
        )
        result = apply_policy(sample_text, sample_detections, policy, Direction.INBOUND)

        assert len(result.original_text_hash) == 64  # SHA-256 hex length
        assert result.original_text_hash.isalnum()

    def test_empty_detections(self, sample_text):
        policy = PolicyConfig(version="test_v1", inbound={}, outbound={})
        result = apply_policy(sample_text, [], policy, Direction.INBOUND)

        assert result.mutated_text == sample_text
        assert result.mutations == []
        assert result.decisions == []
        assert not result.has_review_flag
