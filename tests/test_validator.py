"""Tests for bola_ai.agent.validator — mechanical finding validation."""
from __future__ import annotations

import json
import pytest

from bola_ai.agent.har_analyzer import RawFinding
from bola_ai.agent.validator import FindingValidator, ValidationResult
from bola_ai.rag.fact_index import FactIndex
from bola_ai.rag.har_extractor import HarExtractor


# ---------------------------------------------------------------------------
# Helper: build FactIndex from a minimal HAR
# ---------------------------------------------------------------------------

_SIMPLE_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/users/42",
                    "headers": [{"name": "Authorization", "value": "Bearer tok123"}],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"userId":42,"email":"alice@example.com"}'},
                },
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/users/43",
                    "headers": [{"name": "Authorization", "value": "Bearer tok123"}],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"userId":43,"email":"bob@example.com"}'},
                },
            },
        ]
    }
})


def _make_fact_index() -> FactIndex:
    extractor = HarExtractor()
    artifact = extractor.extract(_SIMPLE_HAR)
    return FactIndex.build(artifact)


def _make_finding(
    entry_id: int = 1,
    pattern_id: str = "1.1",
    evidence_quote: str = "userId",
    confidence: str = "high",
    poc_entry_id: int | None = None,
) -> RawFinding:
    return RawFinding(
        entry_id=entry_id,
        pattern_id=pattern_id,
        pattern_name="ID in path without ownership check",
        evidence_quote=evidence_quote,
        attack_delta="Test attack delta",
        poc_entry_id=poc_entry_id if poc_entry_id is not None else entry_id,
        confidence=confidence,
        note="test",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestValidateOne:
    def test_valid_finding_accepted(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(entry_id=1, evidence_quote="userId")
        result = validator.validate_one(finding, fi)
        assert result.passed is True
        assert result.failure_reason is None

    def test_nonexistent_entry_id_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(entry_id=99, evidence_quote="userId")
        result = validator.validate_one(finding, fi)
        assert result.passed is False
        assert "99" in result.failure_reason

    def test_evidence_quote_not_in_entry_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(entry_id=1, evidence_quote="COMPLETELY_FABRICATED_XYZ")
        result = validator.validate_one(finding, fi)
        assert result.passed is False
        assert "evidence_quote" in result.failure_reason.lower()

    def test_unknown_pattern_id_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(pattern_id="99.99")
        result = validator.validate_one(finding, fi)
        assert result.passed is False
        assert "pattern" in result.failure_reason.lower()

    def test_invalid_confidence_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(confidence="extreme")
        result = validator.validate_one(finding, fi)
        assert result.passed is False
        assert "confidence" in result.failure_reason.lower()

    def test_empty_evidence_quote_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(evidence_quote="   ")
        result = validator.validate_one(finding, fi)
        assert result.passed is False

    def test_poc_entry_id_pointing_to_nonexistent_entry_rejected(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        finding = _make_finding(entry_id=1, poc_entry_id=55)
        result = validator.validate_one(finding, fi)
        assert result.passed is False
        assert "55" in result.failure_reason

    def test_all_known_patterns_accepted(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        known = [
            "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9",
            "1.10", "1.11", "1.12", "1.13",
            "10.1", "10.2", "10.3", "10.4", "10.5", "10.6",
        ]
        for pid in known:
            finding = _make_finding(pattern_id=pid, evidence_quote="userId")
            result = validator.validate_one(finding, fi)
            assert result.passed is True, f"Pattern {pid!r} should be accepted but was rejected: {result.failure_reason}"


class TestValidateAll:
    def test_returns_validation_result(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        findings = [_make_finding(entry_id=1)]
        result = validator.validate_all(findings, fi)
        assert isinstance(result, ValidationResult)

    def test_accepted_and_rejected_split(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        good = _make_finding(entry_id=1, evidence_quote="userId")
        bad = _make_finding(entry_id=99, evidence_quote="userId")
        result = validator.validate_all([good, bad], fi)
        assert len(result.accepted) == 1
        assert len(result.rejected) == 1

    def test_empty_input_gives_empty_result(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        result = validator.validate_all([], fi)
        assert result.accepted == []
        assert result.rejected == []

    def test_all_property_is_full_list(self):
        fi = _make_fact_index()
        validator = FindingValidator()
        good = _make_finding(entry_id=1)
        bad = _make_finding(entry_id=99)
        result = validator.validate_all([good, bad], fi)
        assert len(result.all) == 2
