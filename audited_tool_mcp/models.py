"""Pydantic models for all data structures used across the compliance pipeline.

Every type that crosses a module boundary is defined here. No dict-of-anys —
every field is explicit, typed, and documented.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PIICategory(str, Enum):
    """The 8 PII span categories detected by OpenAI Privacy Filter."""

    ACCOUNT_NUMBER = "account_number"
    PRIVATE_ADDRESS = "private_address"
    PRIVATE_EMAIL = "private_email"
    PRIVATE_PERSON = "private_person"
    PRIVATE_PHONE = "private_phone"
    PRIVATE_URL = "private_url"
    PRIVATE_DATE = "private_date"
    SECRET = "secret"


class PolicyAction(str, Enum):
    """Actions the policy engine can take on a detected PII span."""

    ALLOW = "allow"
    REDACT = "redact"
    HASH = "hash"
    VAULT = "vault"
    REVIEW = "review"
    BLOCK = "block"


class Direction(str, Enum):
    """Whether the scan is on inbound (user query) or outbound (tool result) text."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"


class Role(str, Enum):
    """Roles supported in v1. Passed by the client; v1 trusts the claim."""

    INTERN = "intern"
    ANALYST = "analyst"
    COMPLIANCE_OFFICER = "compliance_officer"


class RequestStatus(str, Enum):
    """Terminal status of a pipeline request."""

    SUCCESS = "success"
    BLOCKED = "blocked"
    REVIEW_QUEUED = "review_queued"
    ERROR = "error"
    RBAC_DENIED = "rbac_denied"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# PII Detection
# ---------------------------------------------------------------------------


class PIIDetection(BaseModel):
    """A single PII span detected by Privacy Filter."""

    category: PIICategory
    start: int = Field(description="Character offset — start of span in original text")
    end: int = Field(description="Character offset — end of span in original text (exclusive)")
    text: str = Field(description="The matched substring")
    confidence: float = Field(
        ge=0.0, le=1.0, description="Mean softmax probability across span tokens"
    )


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------


class PolicyDecision(BaseModel):
    """Record of what the policy engine decided for one PII detection."""

    category: PIICategory
    action: PolicyAction
    reason: str = Field(description="Human-readable explanation for audit trail")


class Mutation(BaseModel):
    """Record of a single text mutation applied by the policy engine."""

    start: int = Field(description="Character offset in the *original* text")
    end: int = Field(description="Character offset in the *original* text (exclusive)")
    category: PIICategory
    action: PolicyAction
    replacement: str = Field(description="The string that replaced the original span")
    vault_ref: str | None = Field(
        default=None, description="Vault reference ID, only if action == VAULT"
    )


class SanitizedInput(BaseModel):
    """Structured result of policy application — not just a string."""

    original_text_hash: str = Field(description="SHA-256 of the original text")
    mutated_text: str = Field(description="Text after all mutations applied")
    mutations: list[Mutation] = Field(default_factory=list)
    decisions: list[PolicyDecision] = Field(default_factory=list)
    has_review_flag: bool = Field(
        default=False, description="True if any detection triggered REVIEW action"
    )
    review_queue_id: str | None = Field(
        default=None, description="UUID for the review queue entry, if flagged"
    )


class RedactionResult(BaseModel):
    """Convenience wrapper for detect + policy application."""

    original_text: str
    sanitized: SanitizedInput
    detections: list[PIIDetection]


# ---------------------------------------------------------------------------
# Policy Configuration
# ---------------------------------------------------------------------------


class CategoryPolicy(BaseModel):
    """Policy for a single PII category in a single direction."""

    action: PolicyAction
    reason: str = ""


# A direction-level policy maps each PII category to an action.
DirectionPolicy = dict[PIICategory, CategoryPolicy]


class PolicyConfig(BaseModel):
    """Complete policy configuration for one role.

    Maps direction → category → action. Carries a version string
    for audit trail reproducibility.
    """

    version: str = Field(description="Policy version identifier for audit trail")
    inbound: dict[PIICategory, CategoryPolicy] = Field(default_factory=dict)
    outbound: dict[PIICategory, CategoryPolicy] = Field(default_factory=dict)


# Full policy map: role → PolicyConfig
PolicyMap = dict[Role, PolicyConfig]


# ---------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------


class Actor(BaseModel):
    """Identity of the request originator."""

    role: Role
    user_id: str
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class RolePermissions(BaseModel):
    """What a role is allowed to do."""

    allowed_tools: set[str] = Field(default_factory=set)
    allowed_tables: set[str] = Field(default_factory=set)
    allowed_columns: dict[str, set[str]] = Field(
        default_factory=dict,
        description="Table name → set of allowed column names. Empty set = all columns.",
    )
    policy_name: str = Field(description="Name of the PolicyConfig to use for this role")


# ---------------------------------------------------------------------------
# Tool Request / Response
# ---------------------------------------------------------------------------


class ToolRequest(BaseModel):
    """Incoming request to the MCP server pipeline."""

    actor: Actor
    tool_name: str
    query: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResponse(BaseModel):
    """Result of tool execution after the full compliance pipeline."""

    result: str
    status: RequestStatus
    review_queue_id: str | None = None
    audit_record_id: str | None = None


# ---------------------------------------------------------------------------
# Audit Record
# ---------------------------------------------------------------------------


class AuditRecord(BaseModel):
    """Structured audit record — one per request, appended to JSONL.

    Never contains raw PII values. Detections contain categories and offsets;
    raw text hashes are stored instead of plaintext for sensitive fields.
    """

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actor: Actor
    tool_name: str
    raw_query_hash: str = Field(description="SHA-256 of the original query")
    inbound_detections: list[PIIDetection] = Field(default_factory=list)
    policy_decisions_inbound: list[PolicyDecision] = Field(default_factory=list)
    tool_input_after_policy: str = Field(
        description="The query text after inbound policy mutations"
    )
    tool_output_raw_hash: str = Field(
        default="", description="SHA-256 of the raw tool output"
    )
    outbound_detections: list[PIIDetection] = Field(default_factory=list)
    policy_decisions_outbound: list[PolicyDecision] = Field(default_factory=list)
    tool_output_final: str = Field(
        default="", description="Tool output after outbound policy mutations"
    )
    status: RequestStatus = RequestStatus.SUCCESS
    latency_ms: float = 0.0
    review_queue_id: str | None = None
    policy_version: str = Field(
        default="", description="Which policy config version was in effect"
    )
    model_version: str = Field(
        default="openai/privacy-filter",
        description="Which Privacy Filter checkpoint was used",
    )


# ---------------------------------------------------------------------------
# Review Queue Entry
# ---------------------------------------------------------------------------


class ReviewQueueEntry(BaseModel):
    """Entry written to the review queue JSONL when a REVIEW action fires."""

    review_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actor: Actor
    tool_name: str
    direction: Direction
    detections: list[PIIDetection]
    query_or_result_hash: str
    status: str = "pending"  # pending | approved | rejected


# ---------------------------------------------------------------------------
# Vault Entry
# ---------------------------------------------------------------------------


class VaultEntry(BaseModel):
    """Entry written to the vault JSONL when a VAULT action fires.

    In production this would be a KMS-backed store. Here it's a
    separate access-controlled JSONL file.
    """

    vault_ref: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    timestamp_utc: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    category: PIICategory
    original_text: str = Field(description="The raw PII value — access-controlled")
    context_hash: str = Field(description="SHA-256 of surrounding context for correlation")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RBACDenied(Exception):
    """Raised when RBAC check fails. Caught by the server to produce audit records."""

    def __init__(self, role: Role, tool_name: str, reason: str):
        self.role = role
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"RBAC denied: role={role.value}, tool={tool_name} — {reason}")


class PolicyViolation(Exception):
    """Raised when a BLOCK policy action fires."""

    def __init__(self, category: PIICategory, direction: Direction, reason: str):
        self.category = category
        self.direction = direction
        self.reason = reason
        super().__init__(
            f"Policy violation: {category.value} in {direction.value} — {reason}"
        )


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def sha256_hash(text: str) -> str:
    """Produce a hex SHA-256 hash of the given text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_short(text: str) -> str:
    """Produce the first 8 characters of the SHA-256 hash."""
    return sha256_hash(text)[:8]
