"""Tests for bola_ai.agent.report_renderer — deterministic report generation."""
from __future__ import annotations

import json
import pytest

from bola_ai.agent.har_analyzer import RawFinding
from bola_ai.agent.report_renderer import ReportRenderer, RenderedReport as HarReport
from bola_ai.agent.validator import ValidatedFinding
from bola_ai.rag.har_extractor import HarExtractor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SIMPLE_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/users/42",
                    "headers": [{"name": "Authorization", "value": "Bearer tok"}],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"userId":42,"email":"alice@example.com"}'},
                },
            }
        ]
    }
})


def _make_validated_finding(
    entry_id: int = 1,
    pattern_id: str = "1.1",
    evidence_quote: str = "userId",
    attack_delta: str = "Replace 42 with any user ID.",
    confidence: str = "high",
    passed: bool = True,
) -> ValidatedFinding:
    raw = RawFinding(
        entry_id=entry_id,
        pattern_id=pattern_id,
        pattern_name="ID in path without ownership check",
        evidence_quote=evidence_quote,
        attack_delta=attack_delta,
        poc_entry_id=entry_id,
        confidence=confidence,
        note="test",
    )
    return ValidatedFinding(raw=raw, passed=passed, failure_reason=None if passed else "test rejection")


def _make_artifact():
    extractor = HarExtractor()
    return extractor.extract(_SIMPLE_HAR)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRenderEmpty:
    def test_empty_findings_produces_report(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        report = renderer.render([], [], artifact)
        assert isinstance(report, HarReport)

    def test_empty_findings_report_mentions_no_findings(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        report = renderer.render([], [], artifact)
        md = report.markdown
        assert (
            "No BOLA" in md
            or "no finding" in md.lower()
            or "**Findings:** 0" in md
            or "clean" in md.lower()
        )


class TestRenderFindings:
    def test_single_finding_rendered(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding()]
        report = renderer.render(findings, [], artifact)
        assert isinstance(report, HarReport)
        assert report.markdown

    def test_report_contains_pattern_id(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding(pattern_id="1.1")]
        report = renderer.render(findings, [], artifact)
        assert "1.1" in report.markdown

    def test_report_contains_evidence_quote(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        evidence = "userId"
        findings = [_make_validated_finding(evidence_quote=evidence)]
        report = renderer.render(findings, [], artifact)
        assert evidence in report.markdown

    def test_report_contains_attack_delta(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding(attack_delta="Replace 42 with any user ID.")]
        report = renderer.render(findings, [], artifact)
        assert "Replace 42" in report.markdown

    def test_report_contains_confidence(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding(confidence="high")]
        report = renderer.render(findings, [], artifact)
        assert "high" in report.markdown.lower()

    def test_curl_command_includes_url(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding(entry_id=1)]
        report = renderer.render(findings, [], artifact)
        # Report should reference the URL from entry 1
        assert "example.com" in report.markdown or "curl" in report.markdown.lower() or "GET" in report.markdown

    def test_rejected_findings_not_in_main_count(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        accepted = [_make_validated_finding(passed=True)]
        rejected = [_make_validated_finding(passed=False, evidence_quote="FABRICATED")]
        report = renderer.render(accepted, rejected, artifact)
        assert report.finding_count == 1

    def test_multiple_patterns_all_render(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        patterns = ["1.1", "1.3", "10.1", "10.6"]
        findings = [_make_validated_finding(pattern_id=p) for p in patterns]
        report = renderer.render(findings, [], artifact)
        for p in patterns:
            assert p in report.markdown, f"Pattern {p} missing from report"

    def test_finding_count_field(self):
        renderer = ReportRenderer()
        artifact = _make_artifact()
        findings = [_make_validated_finding(), _make_validated_finding(pattern_id="1.2")]
        report = renderer.render(findings, [], artifact)
        assert report.finding_count == 2


class TestKnownPatternNames:
    """Verify all 19 pattern IDs map to non-empty, authoritative names."""

    ALL_PATTERNS = [
        "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9",
        "1.10", "1.11", "1.12", "1.13",
        "10.1", "10.2", "10.3", "10.4", "10.5", "10.6",
    ]

    def test_all_patterns_have_names(self):
        from bola_ai.agent.report_renderer import _PATTERN_NAMES
        for pid in self.ALL_PATTERNS:
            assert pid in _PATTERN_NAMES, f"Pattern {pid!r} not in _PATTERN_NAMES"
            assert _PATTERN_NAMES[pid], f"Pattern {pid!r} has empty name"
            assert len(_PATTERN_NAMES[pid]) > 5, f"Pattern {pid!r} name too short: {_PATTERN_NAMES[pid]!r}"
