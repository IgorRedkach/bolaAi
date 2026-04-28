"""Tests for bola_ai.agent.har_analyzer — with mock LLM (no Ollama required)."""
from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from bola_ai.agent.har_analyzer import HarAnalyzer, HarAnalysisResult, RawFinding
from bola_ai.rag.har_extractor import HarExtractor


# ---------------------------------------------------------------------------
# HAR fixture
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

_GOOD_LLM_RESPONSE = json.dumps([
    {
        "entry_id": 1,
        "pattern_id": "1.1",
        "pattern_name": "ID in path without ownership check",
        "evidence_quote": "userId",
        "attack_delta": "Replace 42 with any user ID.",
        "poc_entry_id": 1,
        "confidence": "high",
        "note": "Numeric ID in path",
    }
])

_EMPTY_LLM_RESPONSE = "[]"

_PROSE_WRAPPED_RESPONSE = (
    "Based on my analysis:\n\n"
    + _GOOD_LLM_RESPONSE
    + "\n\nThese are my findings."
)

_MALFORMED_JSON = '{"not": "an array"}'
_PARTIAL_JSON = '[{"entry_id": 1, "pattern_id": "1.1"'  # truncated


def _make_artifact():
    extractor = HarExtractor()
    return extractor.extract(_SIMPLE_HAR)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseResponse:
    """Test _parse() in isolation via analyze() with mocked generate()."""

    def test_valid_response_produces_findings(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value=_GOOD_LLM_RESPONSE):
            result = analyzer.analyze(_make_artifact())
        assert isinstance(result, HarAnalysisResult)
        assert len(result.findings) == 1
        assert result.findings[0].pattern_id == "1.1"
        assert result.findings[0].entry_id == 1

    def test_empty_array_response_gives_empty_findings(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value=_EMPTY_LLM_RESPONSE):
            result = analyzer.analyze(_make_artifact())
        assert result.error is None
        assert result.findings == []

    def test_prose_wrapped_json_still_parsed(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value=_PROSE_WRAPPED_RESPONSE):
            result = analyzer.analyze(_make_artifact())
        assert len(result.findings) == 1

    def test_non_array_json_returns_error(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value=_MALFORMED_JSON):
            result = analyzer.analyze(_make_artifact())
        assert result.error is not None

    def test_no_json_returns_error(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value="I found nothing notable."):
            result = analyzer.analyze(_make_artifact())
        assert result.error is not None

    def test_finding_fields_populated(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", return_value=_GOOD_LLM_RESPONSE):
            result = analyzer.analyze(_make_artifact())
        f = result.findings[0]
        assert f.evidence_quote == "userId"
        assert f.confidence == "high"
        assert f.attack_delta.startswith("Replace")
        assert f.poc_entry_id == 1


class TestFallback:
    """Test that when specialist model fails, fallback model is tried."""

    def test_fallback_called_on_model_error(self):
        analyzer = HarAnalyzer(use_grammar=False)
        call_count = {"n": 0}

        def mock_generate(prompt, model=None, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise ConnectionError("bola-har not available")
            return _GOOD_LLM_RESPONSE

        with patch("bola_ai.agent.har_analyzer.generate", side_effect=mock_generate):
            result = analyzer.analyze(_make_artifact())

        assert call_count["n"] == 2
        assert len(result.findings) == 1

    def test_both_models_fail_returns_error(self):
        analyzer = HarAnalyzer(use_grammar=False)
        with patch("bola_ai.agent.har_analyzer.generate", side_effect=ConnectionError("no model")):
            result = analyzer.analyze(_make_artifact())
        assert result.error is not None


class TestPromptFormat:
    """Verify the prompt sent to the model uses the training format."""

    def test_prompt_contains_instruction_header(self):
        analyzer = HarAnalyzer(use_grammar=False)
        captured = {}

        def mock_generate(prompt, **kwargs):
            captured["prompt"] = prompt
            return _EMPTY_LLM_RESPONSE

        with patch("bola_ai.agent.har_analyzer.generate", side_effect=mock_generate):
            analyzer.analyze(_make_artifact())

        assert "### Instruction" in captured["prompt"]
        assert "### Context" in captured["prompt"]
        assert "### Response" in captured["prompt"]

    def test_prompt_contains_har_entries(self):
        analyzer = HarAnalyzer(use_grammar=False)
        captured = {}

        def mock_generate(prompt, **kwargs):
            captured["prompt"] = prompt
            return _EMPTY_LLM_RESPONSE

        with patch("bola_ai.agent.har_analyzer.generate", side_effect=mock_generate):
            analyzer.analyze(_make_artifact())

        assert "### HAR Entry [1]" in captured["prompt"]
        assert "Method: GET" in captured["prompt"]
