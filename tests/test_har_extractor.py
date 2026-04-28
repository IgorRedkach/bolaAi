"""Tests for bola_ai.rag.har_extractor — deterministic HAR parser."""
from __future__ import annotations

import json
import pytest

from bola_ai.rag.har_extractor import HarExtractor, HarEntry, StructuredArtifact


# ---------------------------------------------------------------------------
# Minimal valid HAR fixtures
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
                    "headers": [{"name": "Content-Type", "value": "application/json"}],
                    "content": {"text": '{"userId":42,"email":"alice@example.com"}'},
                },
            }
        ]
    }
})

_NOISE_ONLY_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://cdn.example.com/app.css",
                    "headers": [],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": "body { margin: 0; }"},
                },
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://www.google-analytics.com/j/collect?v=1&t=pageview",
                    "headers": [],
                    "queryString": [{"name": "v", "value": "1"}, {"name": "t", "value": "pageview"}],
                    "postData": None,
                },
                "response": {"status": 200, "headers": [], "content": {"text": ""}},
            },
        ]
    }
})

_HAR_WITH_AUTH_FLOW = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "POST",
                    "url": "https://accounts.example.com/oauth/token",
                    "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                    "queryString": [],
                    "postData": {"text": "grant_type=authorization_code&code=abc123"},
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"access_token":"ya29.A0"}'},
                },
            },
        ]
    }
})

_HAR_WITH_QUERY_PARAMS = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/reports?ownerId=user-99&format=pdf",
                    "headers": [{"name": "Authorization", "value": "Bearer tok"}],
                    "queryString": [
                        {"name": "ownerId", "value": "user-99"},
                        {"name": "format", "value": "pdf"},
                    ],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"ownerId":"user-99","reports":[]}'},
                },
            }
        ]
    }
})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestIsHar:
    def test_valid_har_detected(self):
        extractor = HarExtractor()
        assert extractor.is_har(_SIMPLE_HAR) is True

    def test_plain_json_not_har(self):
        extractor = HarExtractor()
        assert extractor.is_har('{"foo": "bar"}') is False

    def test_empty_string_not_har(self):
        extractor = HarExtractor()
        assert extractor.is_har("") is False

    def test_html_not_har(self):
        extractor = HarExtractor()
        assert extractor.is_har("<html><body></body></html>") is False


class TestExtract:
    def test_returns_structured_artifact(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        assert isinstance(artifact, StructuredArtifact)

    def test_entry_count(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        assert len(artifact.entries) == 1

    def test_entry_fields(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        entry = artifact.entries[0]
        assert isinstance(entry, HarEntry)
        assert entry.method == "GET"
        assert "42" in entry.path
        assert entry.response_status == 200

    def test_entry_ids_are_one_indexed(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        assert artifact.entries[0].id == 1

    def test_noise_entries_classified(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_NOISE_ONLY_HAR)
        css_entry = artifact.entries[0]
        ga_entry = artifact.entries[1]
        assert css_entry.is_static_resource is True
        assert ga_entry.is_analytics is True

    def test_auth_flow_classified(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_HAR_WITH_AUTH_FLOW)
        entry = artifact.entries[0]
        assert entry.is_auth_flow is True

    def test_bearer_token_extracted(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        entry = artifact.entries[0]
        # Authorization header is stored with original HAR casing ("Authorization")
        # Check case-insensitively across all stored header keys
        auth_val = next(
            (v for k, v in entry.request_headers.items() if k.lower() == "authorization"),
            ""
        )
        assert auth_val != "", "Authorization header should be present in request_headers"
        assert "Bearer" in auth_val or "tok" in auth_val

    def test_query_params_extracted(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_HAR_WITH_QUERY_PARAMS)
        entry = artifact.entries[0]
        assert "ownerId" in entry.query_string
        assert entry.query_string["ownerId"] == ["user-99"]

    def test_path_id_segments_detected(self):
        extractor = HarExtractor()
        # Use a URL with a longer numeric ID (_INT_ID_RE requires \d{4,})
        har_4digit = json.dumps({
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://api.example.com/v1/users/10042",
                            "headers": [],
                            "queryString": [],
                            "postData": None,
                        },
                        "response": {"status": 200, "headers": [], "content": {"text": "{}"}},
                    }
                ]
            }
        })
        artifact = extractor.extract(har_4digit)
        entry = artifact.entries[0]
        # "10042" is a 5-digit numeric ID matching \d{4,}
        assert any("10042" in seg for seg in entry.path_id_segments)


class TestToEntriesListText:
    def test_entries_list_includes_entry_header(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        text = artifact.to_entries_list_text()
        assert "### HAR Entry [1]" in text

    def test_entries_list_includes_method(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        text = artifact.to_entries_list_text()
        assert "Method: GET" in text

    def test_entries_list_includes_url(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        text = artifact.to_entries_list_text()
        assert "v1/users/42" in text

    def test_query_params_formatted_with_colon_indented(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_HAR_WITH_QUERY_PARAMS)
        text = artifact.to_entries_list_text()
        assert "Query Params:" in text
        assert "  ownerId: user-99" in text

    def test_single_newline_between_header_and_entry(self):
        extractor = HarExtractor()
        artifact = extractor.extract(_SIMPLE_HAR)
        text = artifact.to_entries_list_text()
        # There should be exactly one newline between "### HAR Entry [1]" and "Method:"
        idx = text.index("### HAR Entry [1]")
        after_header = text[idx + len("### HAR Entry [1]"):]
        # Should start with "\nMethod:" not "\n\nMethod:"
        assert after_header.startswith("\nMethod:"), (
            f"Expected '\\nMethod:' immediately after header, got: {after_header[:20]!r}"
        )
