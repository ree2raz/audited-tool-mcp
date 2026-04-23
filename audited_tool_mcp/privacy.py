"""Privacy Filter wrapper — local PII detection using OpenAI's privacy-filter model.

Loads openai/privacy-filter via transformers. The model runs locally on CPU
(default) or CUDA. No OpenAI API calls are made — this is non-negotiable.

Public API:
    detect(text) -> list[PIIDetection]
    redact(text, policy_config, direction) -> RedactionResult

The model is lazy-loaded on first call and cached in a module-level singleton.
Thread-safe via a module-level lock.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import TYPE_CHECKING

import torch

from audited_tool_mcp.models import (
    PIICategory,
    PIIDetection,
)

if TYPE_CHECKING:
    from transformers import PreTrainedModel, PreTrainedTokenizerFast

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level singleton for the model
# ---------------------------------------------------------------------------

_model: PreTrainedModel | None = None
_tokenizer: PreTrainedTokenizerFast | None = None
_lock = threading.Lock()
_MODEL_NAME = "openai/privacy-filter"

# Whether to use the mock (regex) detector instead of the real model.
# Set via MOCK_PII=1 env var or by calling use_mock_detector().
_use_mock: bool = os.environ.get("MOCK_PII", "0") == "1"


def use_mock_detector(enabled: bool = True) -> None:
    """Switch between real Privacy Filter model and regex-based mock.

    The mock is for fast testing only. It uses simple regex patterns and
    will NOT match real-world Privacy Filter behavior.
    """
    global _use_mock
    _use_mock = enabled


def _get_model() -> tuple[PreTrainedModel, PreTrainedTokenizerFast]:
    """Lazy-load the Privacy Filter model. Thread-safe with double-check locking."""
    global _model, _tokenizer

    if _model is not None and _tokenizer is not None:
        return _model, _tokenizer

    with _lock:
        # Double-check after acquiring lock
        if _model is not None and _tokenizer is not None:
            return _model, _tokenizer

        from transformers import AutoModelForTokenClassification, AutoTokenizer

        device = os.environ.get("PRIVACY_FILTER_DEVICE", "cpu")
        logger.info("Loading Privacy Filter model '%s' on device '%s'...", _MODEL_NAME, device)

        _tokenizer = AutoTokenizer.from_pretrained(_MODEL_NAME)
        _model = AutoModelForTokenClassification.from_pretrained(
            _MODEL_NAME,
            device_map=device,
        )
        _model.eval()

        logger.info(
            "Privacy Filter loaded: %d labels, device=%s",
            _model.config.num_labels,
            device,
        )
        return _model, _tokenizer


# ---------------------------------------------------------------------------
# BIOES label parsing
# ---------------------------------------------------------------------------

# Privacy Filter label format: "B-private_person", "I-private_person",
# "E-private_person", "S-private_person", "O"
# Total: 1 (O) + 8 categories × 4 tags = 33

_BIOES_PREFIXES = {"B", "I", "O", "E", "S"}

# Map from Privacy Filter category strings to our enum
_CATEGORY_MAP: dict[str, PIICategory] = {cat.value: cat for cat in PIICategory}


def _parse_label(label: str) -> tuple[str, PIICategory | None]:
    """Parse a BIOES label string into (prefix, category).

    Returns ("O", None) for the background class.
    """
    if label == "O":
        return ("O", None)

    # Expected format: "B-category_name" or "S-category_name" etc.
    parts = label.split("-", 1)
    if len(parts) != 2:
        return ("O", None)

    prefix, category_str = parts
    if prefix not in _BIOES_PREFIXES:
        return ("O", None)

    category = _CATEGORY_MAP.get(category_str)
    if category is None:
        return ("O", None)

    return (prefix, category)


def _decode_bioes_spans(
    labels: list[str],
    token_offsets: list[tuple[int, int] | None],
    token_probs: list[float],
    original_text: str,
) -> list[PIIDetection]:
    """Decode BIOES-tagged token labels into contiguous PIIDetection spans.

    Handles:
    - S (single-token span)
    - B → I* → E (multi-token span)
    - Edge cases: orphaned I/E tokens are skipped
    """
    detections: list[PIIDetection] = []
    i = 0
    n = len(labels)

    while i < n:
        prefix, category = _parse_label(labels[i])

        if prefix == "S" and category is not None:
            # Single-token span
            offsets = token_offsets[i]
            if offsets is not None and offsets != (0, 0):
                char_start, char_end = offsets
                detections.append(
                    PIIDetection(
                        category=category,
                        start=char_start,
                        end=char_end,
                        text=original_text[char_start:char_end],
                        confidence=token_probs[i],
                    )
                )
            i += 1

        elif prefix == "B" and category is not None:
            # Start of multi-token span — collect I* then E
            span_start_offset = token_offsets[i]
            span_probs = [token_probs[i]]
            j = i + 1

            while j < n:
                next_prefix, next_cat = _parse_label(labels[j])
                if next_cat == category and next_prefix == "I":
                    span_probs.append(token_probs[j])
                    j += 1
                elif next_cat == category and next_prefix == "E":
                    span_probs.append(token_probs[j])
                    j += 1
                    break
                else:
                    # Broken span — use what we have up to here
                    break

            # Compute character offsets from first to last token in span
            span_end_offset = token_offsets[j - 1]

            if (
                span_start_offset is not None
                and span_end_offset is not None
                and span_start_offset != (0, 0)
            ):
                char_start = span_start_offset[0]
                char_end = span_end_offset[1]
                avg_confidence = sum(span_probs) / len(span_probs)

                detections.append(
                    PIIDetection(
                        category=category,
                        start=char_start,
                        end=char_end,
                        text=original_text[char_start:char_end],
                        confidence=avg_confidence,
                    )
                )

            i = j

        else:
            # O, orphaned I/E, or unrecognized — skip
            i += 1

    return detections


# ---------------------------------------------------------------------------
# Mock detector (regex-based, for testing only)
# ---------------------------------------------------------------------------

# Simple regex patterns — NOT production quality. Clearly documented as non-production.
_MOCK_PATTERNS: list[tuple[PIICategory, re.Pattern[str]]] = [
    # Email addresses
    (PIICategory.PRIVATE_EMAIL, re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    # Phone numbers (various formats)
    (PIICategory.PRIVATE_PHONE, re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    )),
    # Account numbers (digit sequences with dashes, 8+ digits)
    (PIICategory.ACCOUNT_NUMBER, re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}(?:[-\s]?\d{4})?\b")),
    # SSN-like patterns
    (PIICategory.SECRET, re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    # URLs
    (PIICategory.PRIVATE_URL, re.compile(r"https?://[^\s]+")),
    # Dates (common formats)
    (PIICategory.PRIVATE_DATE, re.compile(
        r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b"
    )),
    # Addresses (simple heuristic: number + street name + type)
    (PIICategory.PRIVATE_ADDRESS, re.compile(
        r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:St|Ave|Blvd|Dr|Ln|Rd|Way|Ct|Pl|Circle|Pkwy)"
        r"\.?\b",
        re.IGNORECASE,
    )),
    # Person names — capitalized word sequences (very crude, high false positive rate)
    # Only match 2-3 consecutive capitalized words not at sentence start
    (PIICategory.PRIVATE_PERSON, re.compile(
        r"(?:(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+)?(?:[A-Z][a-z]+\s+){1,2}[A-Z][a-z]+"
    )),
]


def _mock_detect(text: str) -> list[PIIDetection]:
    """Regex-based mock PII detector. For testing only — not production quality."""
    detections: list[PIIDetection] = []
    for category, pattern in _MOCK_PATTERNS:
        for match in pattern.finditer(text):
            detections.append(
                PIIDetection(
                    category=category,
                    start=match.start(),
                    end=match.end(),
                    text=match.group(),
                    confidence=0.95,  # Mock always returns high confidence
                )
            )

    # Sort by start offset, remove overlapping detections (keep longest)
    detections.sort(key=lambda d: (d.start, -(d.end - d.start)))
    filtered: list[PIIDetection] = []
    last_end = -1
    for det in detections:
        if det.start >= last_end:
            filtered.append(det)
            last_end = det.end

    return filtered


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect(text: str) -> list[PIIDetection]:
    """Detect PII spans in the given text.

    Uses OpenAI Privacy Filter (1.5B parameter local model) by default.
    Falls back to regex-based mock if MOCK_PII=1 or use_mock_detector(True).

    Returns:
        Sorted list of PIIDetection objects with character offsets.
    """
    if not text or not text.strip():
        return []

    if _use_mock:
        logger.debug("Using mock PII detector (regex-based)")
        return _mock_detect(text)

    model, tokenizer = _get_model()

    # Tokenize with offset mapping for character-level alignment
    encoding = tokenizer(
        text,
        return_tensors="pt",
        return_offsets_mapping=True,
        truncation=True,
        max_length=128000,  # Privacy Filter supports 128k context window
    )

    offset_mapping = encoding.pop("offset_mapping")[0].tolist()  # list of (start, end) tuples
    inputs = {k: v.to(model.device) for k, v in encoding.items()}

    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits[0]  # Shape: [T, 33]

    # Softmax for confidence scores
    probs = torch.nn.functional.softmax(logits, dim=-1)

    # Argmax per token
    predicted_ids = logits.argmax(dim=-1).tolist()

    # Get label names and per-token confidence (max prob)
    labels: list[str] = []
    token_probs: list[float] = []
    for idx, pred_id in enumerate(predicted_ids):
        label = model.config.id2label.get(pred_id, "O")
        labels.append(label)
        token_probs.append(probs[idx, pred_id].item())

    # BIOES span decoding
    detections = _decode_bioes_spans(labels, offset_mapping, token_probs, text)

    # Sort by start offset
    detections.sort(key=lambda d: d.start)

    return detections


def get_model_version() -> str:
    """Return the model identifier for audit records."""
    return _MODEL_NAME
