"""Policy engine — configurable per-category PII handling with six actions.

Policies are Pydantic models, not YAML/JSON blobs. Type safety over config
flexibility. Each of the 8 Privacy Filter categories maps to one of:
ALLOW, REDACT, HASH, VAULT, REVIEW, BLOCK.

The engine processes detections in reverse offset order to preserve character
positions during mutation. Returns a SanitizedInput with structured mutation
records, not just a mutated string.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path

from audited_tool_mcp.models import (
    CategoryPolicy,
    Direction,
    Mutation,
    PIICategory,
    PIIDetection,
    PolicyAction,
    PolicyConfig,
    PolicyDecision,
    PolicyMap,
    PolicyViolation,
    ReviewQueueEntry,
    Role,
    SanitizedInput,
    VaultEntry,
    sha256_hash,
    sha256_short,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Vault and review queue file writers
# ---------------------------------------------------------------------------

_VAULT_PATH = os.environ.get("VAULT_PATH", "./vault.jsonl")
_REVIEW_QUEUE_PATH = os.environ.get("REVIEW_QUEUE_PATH", "./review_queue.jsonl")


def _write_vault_entry(entry: VaultEntry) -> None:
    """Append a vault entry to the vault JSONL file."""
    with open(_VAULT_PATH, "a") as f:
        f.write(entry.model_dump_json() + "\n")


def _write_review_entry(entry: ReviewQueueEntry) -> None:
    """Append a review queue entry to the review queue JSONL file."""
    with open(_REVIEW_QUEUE_PATH, "a") as f:
        f.write(entry.model_dump_json() + "\n")


# ---------------------------------------------------------------------------
# Bundled policies
# ---------------------------------------------------------------------------


def _make_all_categories_policy(action: PolicyAction, reason: str) -> dict[PIICategory, CategoryPolicy]:
    """Helper: same action for all 8 categories."""
    return {cat: CategoryPolicy(action=action, reason=reason) for cat in PIICategory}


STRICT_FINANCIAL = PolicyConfig(
    version="strict_financial_v1",
    inbound={
        PIICategory.ACCOUNT_NUMBER: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact account numbers in inbound queries"
        ),
        PIICategory.PRIVATE_ADDRESS: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Addresses allowed in inbound queries for lookups"
        ),
        PIICategory.PRIVATE_EMAIL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Emails allowed in inbound queries for lookups"
        ),
        PIICategory.PRIVATE_PERSON: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Names allowed in inbound queries for lookups"
        ),
        PIICategory.PRIVATE_PHONE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Phones allowed in inbound queries for lookups"
        ),
        PIICategory.PRIVATE_URL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="URLs allowed in inbound queries"
        ),
        PIICategory.PRIVATE_DATE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Dates allowed in inbound queries"
        ),
        PIICategory.SECRET: CategoryPolicy(
            action=PolicyAction.BLOCK, reason="Secrets must never appear in inbound queries"
        ),
    },
    outbound={
        PIICategory.ACCOUNT_NUMBER: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact account numbers in results"
        ),
        PIICategory.PRIVATE_ADDRESS: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact addresses in results"
        ),
        PIICategory.PRIVATE_EMAIL: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact emails in results"
        ),
        PIICategory.PRIVATE_PERSON: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact person names in results"
        ),
        PIICategory.PRIVATE_PHONE: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact phone numbers in results"
        ),
        PIICategory.PRIVATE_URL: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact URLs in results"
        ),
        PIICategory.PRIVATE_DATE: CategoryPolicy(
            action=PolicyAction.REVIEW, reason="Dates flagged for review in results"
        ),
        PIICategory.SECRET: CategoryPolicy(
            action=PolicyAction.BLOCK, reason="Secrets must never appear in results"
        ),
    },
)

PERMISSIVE_ANALYST = PolicyConfig(
    version="permissive_analyst_v1",
    inbound={
        PIICategory.ACCOUNT_NUMBER: CategoryPolicy(
            action=PolicyAction.HASH, reason="Hash account numbers for identity consistency"
        ),
        PIICategory.PRIVATE_ADDRESS: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Addresses allowed for analyst lookups"
        ),
        PIICategory.PRIVATE_EMAIL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Emails allowed for analyst lookups"
        ),
        PIICategory.PRIVATE_PERSON: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Names allowed for analyst lookups"
        ),
        PIICategory.PRIVATE_PHONE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Phones allowed for analyst lookups"
        ),
        PIICategory.PRIVATE_URL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="URLs allowed for analyst queries"
        ),
        PIICategory.PRIVATE_DATE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Dates allowed for analyst queries"
        ),
        PIICategory.SECRET: CategoryPolicy(
            action=PolicyAction.BLOCK, reason="Secrets must never appear in queries"
        ),
    },
    outbound={
        PIICategory.ACCOUNT_NUMBER: CategoryPolicy(
            action=PolicyAction.REDACT, reason="Redact full account numbers in results"
        ),
        PIICategory.PRIVATE_ADDRESS: CategoryPolicy(
            action=PolicyAction.REVIEW, reason="Addresses flagged for review"
        ),
        PIICategory.PRIVATE_EMAIL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Emails visible to analysts"
        ),
        PIICategory.PRIVATE_PERSON: CategoryPolicy(
            action=PolicyAction.HASH, reason="Hash names for identity consistency"
        ),
        PIICategory.PRIVATE_PHONE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Phones visible to analysts"
        ),
        PIICategory.PRIVATE_URL: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="URLs visible to analysts"
        ),
        PIICategory.PRIVATE_DATE: CategoryPolicy(
            action=PolicyAction.ALLOW, reason="Dates visible to analysts"
        ),
        PIICategory.SECRET: CategoryPolicy(
            action=PolicyAction.VAULT, reason="Secrets vaulted in results"
        ),
    },
)

# Map policy names to configs
BUNDLED_POLICIES: dict[str, PolicyConfig] = {
    "strict_financial": STRICT_FINANCIAL,
    "permissive_analyst": PERMISSIVE_ANALYST,
}


def get_policy(name: str) -> PolicyConfig:
    """Retrieve a bundled policy by name."""
    if name not in BUNDLED_POLICIES:
        raise ValueError(f"Unknown policy: {name}. Available: {list(BUNDLED_POLICIES.keys())}")
    return BUNDLED_POLICIES[name]


# ---------------------------------------------------------------------------
# Numeric false-positive suppression for phone detections
# ---------------------------------------------------------------------------

import re as _re

_NUMERIC_VALUE_PATTERN = _re.compile(r'^[\d.\-]+$')


def _is_numeric_json_value(text: str, start: int, end: int) -> bool:
    """Check if a detection span is a numeric JSON value.

    Privacy Filter can mistake numeric sequences in financial data
    (e.g., 496959.67 in JSON) for phone numbers. Suppress redaction
    when the detected span is purely numeric in JSON number context.
    """
    detected = text[start:end]
    if not _NUMERIC_VALUE_PATTERN.match(detected):
        return False
    before = text[max(0, start - 3):start]
    after = text[end:min(len(text), end + 3)]
    numeric_before = bool(_re.search(r'[:\[,\s]\s*$', before))
    numeric_after = bool(_re.search(r'^[\s\]]*[,}\]]', after)) or not after.strip()
    return numeric_before and numeric_after


# ---------------------------------------------------------------------------
# Policy application
# ---------------------------------------------------------------------------


def apply_policy(
    text: str,
    detections: list[PIIDetection],
    policy: PolicyConfig,
    direction: Direction,
    request_id: str = "",
    actor: object | None = None,
    tool_name: str = "",
) -> SanitizedInput:
    """Apply policy actions to detected PII spans, returning structured SanitizedInput.

    Processes detections in reverse offset order to preserve character positions
    during text mutation.

    Args:
        text: Original text to process
        detections: PII spans detected by Privacy Filter
        policy: Policy configuration for the actor's role
        direction: Whether this is inbound (query) or outbound (result)
        request_id: For audit correlation
        actor: Actor model for review queue entries
        tool_name: For review queue entries

    Returns:
        SanitizedInput with mutated text, mutation records, and decisions

    Raises:
        PolicyViolation: If any detection triggers a BLOCK action
    """
    direction_policy = policy.inbound if direction == Direction.INBOUND else policy.outbound

    original_hash = sha256_hash(text)
    mutated = text
    mutations: list[Mutation] = []
    decisions: list[PolicyDecision] = []
    review_detections: list[PIIDetection] = []
    has_review = False
    review_queue_id: str | None = None

    # Process in reverse order to preserve character offsets
    sorted_detections = sorted(detections, key=lambda d: d.start, reverse=True)

    for det in sorted_detections:
        cat_policy = direction_policy.get(det.category)

        if cat_policy is None:
            # No policy for this category — default to ALLOW
            decisions.append(PolicyDecision(
                category=det.category,
                action=PolicyAction.ALLOW,
                reason=f"No policy defined for {det.category.value} in {direction.value}",
            ))
            continue

        action = cat_policy.action
        reason = cat_policy.reason

        if action == PolicyAction.ALLOW:
            decisions.append(PolicyDecision(
                category=det.category, action=action, reason=reason
            ))

        elif action == PolicyAction.REDACT:
            # Suppress numeric false positives for phone detections.
            # Balance values like 496959.67 get mistaken for phone numbers
            # by the model. If the span is purely numeric in JSON number
            # context, treat as ALLOW instead of redacting.
            if det.category == PIICategory.PRIVATE_PHONE and _is_numeric_json_value(
                mutated, det.start, det.end
            ):
                decisions.append(PolicyDecision(
                    category=det.category,
                    action=PolicyAction.ALLOW,
                    reason="Numeric value in JSON context — suppressed phone false positive",
                ))
            else:
                replacement = f"[{det.category.value}]"
                mutated = mutated[:det.start] + replacement + mutated[det.end:]
                mutations.append(Mutation(
                    start=det.start,
                    end=det.end,
                    category=det.category,
                    action=action,
                    replacement=replacement,
                ))
                decisions.append(PolicyDecision(
                    category=det.category, action=action, reason=reason
                ))

        elif action == PolicyAction.HASH:
            hash_val = sha256_short(det.text)
            replacement = f"[{det.category.value}:{hash_val}]"
            mutated = mutated[:det.start] + replacement + mutated[det.end:]
            mutations.append(Mutation(
                start=det.start,
                end=det.end,
                category=det.category,
                action=action,
                replacement=replacement,
            ))
            decisions.append(PolicyDecision(
                category=det.category, action=action, reason=reason
            ))

        elif action == PolicyAction.VAULT:
            vault_ref = str(uuid.uuid4())
            replacement = f"[{det.category.value}:vault-ref-{vault_ref}]"
            mutated = mutated[:det.start] + replacement + mutated[det.end:]

            # Write to vault file
            vault_entry = VaultEntry(
                vault_ref=vault_ref,
                request_id=request_id,
                category=det.category,
                original_text=det.text,
                context_hash=sha256_hash(text[max(0, det.start - 50):det.end + 50]),
            )
            _write_vault_entry(vault_entry)

            mutations.append(Mutation(
                start=det.start,
                end=det.end,
                category=det.category,
                action=action,
                replacement=replacement,
                vault_ref=vault_ref,
            ))
            decisions.append(PolicyDecision(
                category=det.category, action=action, reason=reason
            ))

        elif action == PolicyAction.REVIEW:
            # Leave text intact, flag for human review
            has_review = True
            review_detections.append(det)

            decisions.append(PolicyDecision(
                category=det.category, action=action, reason=reason
            ))

        elif action == PolicyAction.BLOCK:
            # Halt the request immediately
            raise PolicyViolation(
                category=det.category,
                direction=direction,
                reason=f"BLOCK policy triggered: {reason}",
            )

    # Write a single review queue entry if any detections triggered REVIEW
    if has_review and review_detections:
        review_queue_id = str(uuid.uuid4())
        from audited_tool_mcp.models import Actor as ActorModel
        review_entry = ReviewQueueEntry(
            review_id=review_queue_id,
            request_id=request_id,
            actor=actor if isinstance(actor, ActorModel) else ActorModel(
                role=Role.ANALYST, user_id="unknown", session_id="unknown"
            ),
            tool_name=tool_name,
            direction=direction,
            detections=review_detections[::-1],  # Reverse back to original order
            query_or_result_hash=original_hash,
        )
        _write_review_entry(review_entry)

    return SanitizedInput(
        original_text_hash=original_hash,
        mutated_text=mutated,
        mutations=mutations,
        decisions=decisions,
        has_review_flag=has_review,
        review_queue_id=review_queue_id,
    )
