"""Pipeline types -- serializable data models for the orchestration boundary.

These types bridge the existing auditguard-mcp models (Actor, AuditRecord, etc.)
with the new pipeline architecture. They are intentionally separate from the
existing models to maintain clear abstraction layers.

All types use Pydantic for JSON serialization (required by Temporal activities).
"""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field

from auditguard_mcp.models import Role as _Role


# Re-export existing Role enum for convenience
Role = _Role


class PolicyMode(str, Enum):
    """High-level policy mode -- resolves to a concrete PolicyConfig name."""
    PERMISSIVE = "permissive"
    STRICT = "strict"


class PipelineAction(str, Enum):
    """Aggregate action after applying policy to all detections in one direction.

    This is distinct from models.PolicyAction, which governs individual PII spans
    (allow, redact, hash, vault, review, block). PipelineAction is the result of
    aggregating all span-level decisions into a pipeline-level gate decision.
    """
    ALLOW = "allow"
    TRANSFORM = "transform"
    DENY = "deny"
    AUDIT_AND_ALLOW = "audit_and_allow"
    HUMAN_REVIEW = "human_review"
    BLOCK = "block"


class AuditRequest(BaseModel):
    """Everything needed to run one audit pipeline.

    scan_text is the text scanned for inbound PII (e.g., the SQL query or
    natural-language description). tool_input contains the actual tool arguments.
    """

    request_id: str
    role: Role
    tool_name: str
    tool_input: dict[str, Any] = Field(default_factory=dict)
    scan_text: str = ""  # text to scan for inbound PII
    requester: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuditContext(BaseModel):
    """Runtime configuration for a single pipeline execution."""

    policy_mode: PolicyMode = PolicyMode.PERMISSIVE
    pii_threshold: float = 0.7
    timeout_seconds: int = 30
    max_output_tokens: int = 4096


class PIIScanResult(BaseModel):
    """Result of running the Privacy Filter on a text."""

    has_pii: bool
    confidence: float  # max confidence across all detections
    detected_types: list[str] = Field(default_factory=list)
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw detection dicts (serializable via Pydantic)",
    )


class PipelineDecision(BaseModel):
    """Pipeline-level decision produced by aggregating span-level policy actions."""

    action: PipelineAction
    reason: str
    triggered_rules: list[str] = Field(default_factory=list)
    sanitized_text: str = ""
    has_review_flag: bool = False
    review_queue_id: str | None = None
    categories: list[str] = Field(default_factory=list)  # detected PII categories


class StageResult(BaseModel):
    """Generic wrapper for a single stage's execution result."""

    stage_name: str
    success: bool
    duration_ms: int = 0
    output: Any | None = None
    error: str | None = None


class PipelineLogEntry(BaseModel):
    """Final entry written by the audit log stage.

    Wraps the existing AuditRecord and adds the backend discriminator.
    """

    request_id: str
    timestamp: datetime
    role: Role
    tool_name: str
    decisions: list[PipelineDecision]
    final_action: PipelineAction
    duration_ms: int
    backend: Literal["async", "temporal"]
    status: str = "success"
    error: str | None = None


class ToolRegistryEntry(BaseModel):
    """Descriptor for a registered tool (not the callable itself)."""

    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict)
