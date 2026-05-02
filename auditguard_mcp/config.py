"""Configuration — backend selection and pipeline tuning.

Reads from environment variables with sensible defaults.
"""
from __future__ import annotations

import os
from typing import Literal

from pydantic import BaseModel, Field


class AuditConfig(BaseModel):
    """Runtime configuration for the auditguard-mcp server.

    Fields:
        backend: Orchestration backend — 'async' (default) or 'temporal'.
        policy_mode: High-level policy mode — 'permissive' or 'strict'.
        pii_threshold: Minimum confidence for a PII detection to be acted upon.
        timeout_seconds: Per-tool execution timeout.
        max_output_tokens: Max output size before truncation.
        temporal_address: Temporal server gRPC address (only used if backend=='temporal').
        temporal_task_queue: Temporal task queue name (only used if backend=='temporal').
    """

    backend: Literal["async", "temporal"] = Field(
        default="async",
        description="Orchestration backend. 'async' for low-latency single-process. "
        "'temporal' for durable execution.",
    )
    policy_mode: Literal["permissive", "strict"] = "permissive"
    pii_threshold: float = 0.7
    timeout_seconds: int = 30
    max_output_tokens: int = 4096

    # Temporal-specific (only used if backend=='temporal')
    temporal_address: str = "localhost:7233"
    temporal_task_queue: str = "auditguard-pipeline"

    @classmethod
    def from_env(cls) -> "AuditConfig":
        """Build config from environment variables."""
        return cls(
            backend=os.getenv("AUDITGUARD_BACKEND", "async"),
            policy_mode=os.getenv("AUDITGUARD_POLICY_MODE", "permissive"),
            pii_threshold=float(os.getenv("AUDITGUARD_PII_THRESHOLD", "0.7")),
            timeout_seconds=int(os.getenv("AUDITGUARD_TIMEOUT_SECONDS", "30")),
            max_output_tokens=int(os.getenv("AUDITGUARD_MAX_OUTPUT_TOKENS", "4096")),
            temporal_address=os.getenv("TEMPORAL_ADDRESS", "localhost:7233"),
            temporal_task_queue=os.getenv("TEMPORAL_TASK_QUEUE", "auditguard-pipeline"),
        )


# Module-level singleton
_CONFIG: AuditConfig | None = None


def get_config() -> AuditConfig:
    """Return the cached AuditConfig singleton.

    Loads from environment on first call.
    """
    global _CONFIG
    if _CONFIG is None:
        _CONFIG = AuditConfig.from_env()
    return _CONFIG


def set_config(config: AuditConfig) -> None:
    """Override the cached config (useful in tests)."""
    global _CONFIG
    _CONFIG = config
