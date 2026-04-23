"""Tests for the Privacy Filter wrapper (audited_tool_mcp.privacy).

Validates BIOES span decoding logic and the mock detector against
5 hand-crafted examples. Real model tests are marked with a separate
marker to allow fast CI runs without downloading the 1.5B model.
"""

from __future__ import annotations

import pytest

from audited_tool_mcp.models import PIICategory, PIIDetection
from audited_tool_mcp.privacy import (
    _decode_bioes_spans,
    _mock_detect,
    _parse_label,
    detect,
    use_mock_detector,
)


# ---------------------------------------------------------------------------
# Test BIOES label parsing
# ---------------------------------------------------------------------------


class TestParseBIOESLabel:
    def test_outside_label(self):
        prefix, cat = _parse_label("O")
        assert prefix == "O"
        assert cat is None

    def test_begin_label(self):
        prefix, cat = _parse_label("B-private_person")
        assert prefix == "B"
        assert cat == PIICategory.PRIVATE_PERSON

    def test_single_label(self):
        prefix, cat = _parse_label("S-private_email")
        assert prefix == "S"
        assert cat == PIICategory.PRIVATE_EMAIL

    def test_inside_label(self):
        prefix, cat = _parse_label("I-account_number")
        assert prefix == "I"
        assert cat == PIICategory.ACCOUNT_NUMBER

    def test_end_label(self):
        prefix, cat = _parse_label("E-private_phone")
        assert prefix == "E"
        assert cat == PIICategory.PRIVATE_PHONE

    def test_unknown_category(self):
        prefix, cat = _parse_label("B-unknown_category")
        assert prefix == "O"
        assert cat is None

    def test_malformed_label(self):
        prefix, cat = _parse_label("GARBAGE")
        assert prefix == "O"
        assert cat is None

    def test_empty_string(self):
        prefix, cat = _parse_label("")
        assert prefix == "O"
        assert cat is None


# ---------------------------------------------------------------------------
# Test BIOES span decoding
# ---------------------------------------------------------------------------


class TestBIOESSpanDecoding:
    def test_single_token_span(self):
        """S-private_email on a single token → one detection."""
        text = "Email: alice@example.com please"
        labels = ["O", "S-private_email", "O"]
        offsets = [(0, 6), (7, 24), (25, 31)]
        probs = [0.99, 0.98, 0.99]

        result = _decode_bioes_spans(labels, offsets, probs, text)

        assert len(result) == 1
        assert result[0].category == PIICategory.PRIVATE_EMAIL
        assert result[0].text == "alice@example.com"
        assert result[0].confidence == pytest.approx(0.98)

    def test_multi_token_span(self):
        """B-private_person → I-private_person → E-private_person → one detection."""
        text = "My name is Alice Marie Smith okay"
        labels = ["O", "O", "O", "B-private_person", "I-private_person", "E-private_person", "O"]
        offsets = [(0, 2), (3, 7), (8, 10), (11, 16), (17, 22), (23, 28), (29, 33)]
        probs = [0.99, 0.99, 0.99, 0.95, 0.93, 0.96, 0.99]

        result = _decode_bioes_spans(labels, offsets, probs, text)

        assert len(result) == 1
        assert result[0].category == PIICategory.PRIVATE_PERSON
        assert result[0].text == "Alice Marie Smith"
        assert result[0].start == 11
        assert result[0].end == 28
        assert result[0].confidence == pytest.approx((0.95 + 0.93 + 0.96) / 3)

    def test_no_detections(self):
        """All O labels → no detections."""
        text = "No PII here"
        labels = ["O", "O", "O"]
        offsets = [(0, 2), (3, 6), (7, 11)]
        probs = [0.99, 0.99, 0.99]

        result = _decode_bioes_spans(labels, offsets, probs, text)
        assert result == []

    def test_multiple_spans(self):
        """Two separate spans detected."""
        text = "Call Alice at alice@example.com"
        labels = ["O", "S-private_person", "O", "S-private_email"]
        offsets = [(0, 4), (5, 10), (11, 13), (14, 31)]
        probs = [0.99, 0.97, 0.99, 0.96]

        result = _decode_bioes_spans(labels, offsets, probs, text)

        assert len(result) == 2
        assert result[0].category == PIICategory.PRIVATE_PERSON
        assert result[0].text == "Alice"
        assert result[1].category == PIICategory.PRIVATE_EMAIL
        assert result[1].text == "alice@example.com"

    def test_special_token_offsets_skipped(self):
        """Tokens with (0,0) offsets (special tokens) are skipped."""
        text = "Hello Alice"
        labels = ["O", "O", "S-private_person", "O"]
        offsets = [(0, 0), (0, 5), (6, 11), (0, 0)]  # First and last are special tokens
        probs = [0.0, 0.99, 0.95, 0.0]

        result = _decode_bioes_spans(labels, offsets, probs, text)

        assert len(result) == 1
        assert result[0].text == "Alice"


# ---------------------------------------------------------------------------
# Test mock detector
# ---------------------------------------------------------------------------


class TestMockDetector:
    """Tests for the regex-based mock detector used with --mock-pii flag."""

    def test_detect_person_name(self):
        """Mock should detect multi-word capitalized names."""
        detections = _mock_detect("Please contact Alice Marie Smith about the account.")
        person_dets = [d for d in detections if d.category == PIICategory.PRIVATE_PERSON]
        assert len(person_dets) >= 1
        assert any("Alice" in d.text for d in person_dets)

    def test_detect_email(self):
        detections = _mock_detect("Email me at alice@example.com for details.")
        email_dets = [d for d in detections if d.category == PIICategory.PRIVATE_EMAIL]
        assert len(email_dets) == 1
        assert email_dets[0].text == "alice@example.com"

    def test_detect_phone(self):
        detections = _mock_detect("Call 555-123-4567 for support.")
        phone_dets = [d for d in detections if d.category == PIICategory.PRIVATE_PHONE]
        assert len(phone_dets) == 1
        assert "555-123-4567" in phone_dets[0].text

    def test_detect_account_number(self):
        detections = _mock_detect("Account number 1234-5678-9012 is active.")
        acct_dets = [d for d in detections if d.category == PIICategory.ACCOUNT_NUMBER]
        assert len(acct_dets) == 1
        assert "1234-5678-9012" in acct_dets[0].text

    def test_no_pii(self):
        detections = _mock_detect("No PII here, just weather and sports news.")
        assert len(detections) == 0

    def test_non_overlapping(self):
        """Mock detector should not return overlapping detections."""
        detections = _mock_detect(
            "Contact John Smith at john@example.com or 555-123-4567"
        )
        for i in range(len(detections) - 1):
            assert detections[i].end <= detections[i + 1].start


# ---------------------------------------------------------------------------
# Test the public detect() function with mock mode
# ---------------------------------------------------------------------------


class TestDetectPublicAPI:
    """Tests using the public detect() function in mock mode."""

    @pytest.fixture(autouse=True)
    def _enable_mock(self):
        use_mock_detector(True)
        yield
        use_mock_detector(False)

    def test_detect_returns_pii_detections(self):
        result = detect("My name is Alice Smith and my email is alice@example.com")
        assert isinstance(result, list)
        assert all(isinstance(d, PIIDetection) for d in result)
        # Should find at least an email
        categories = {d.category for d in result}
        assert PIICategory.PRIVATE_EMAIL in categories

    def test_detect_empty_string(self):
        result = detect("")
        assert result == []

    def test_detect_whitespace_only(self):
        result = detect("   \n\t  ")
        assert result == []

    def test_detect_no_pii(self):
        result = detect("The weather forecast calls for sunny skies tomorrow.")
        assert len(result) == 0

    def test_detect_multiple_categories(self):
        text = "Contact John Smith at john@example.com or 555-123-4567"
        result = detect(text)
        categories = {d.category for d in result}
        # Should find email and phone at minimum
        assert PIICategory.PRIVATE_EMAIL in categories
        assert PIICategory.PRIVATE_PHONE in categories
