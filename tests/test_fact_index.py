"""Tests for bola_ai.rag.fact_index — verifiable fact extraction and grounding."""
from __future__ import annotations

import json
import pytest

from bola_ai.rag.fact_index import FactIndex, EntryFacts
from bola_ai.rag.har_extractor import HarExtractor


# ---------------------------------------------------------------------------
# HAR fixtures
# ---------------------------------------------------------------------------

_SINGLE_ENTRY_HAR = json.dumps({
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
            }
        ]
    }
})

_TWO_ENTRY_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/accounts/ACC-001",
                    "headers": [{"name": "Authorization", "value": "Bearer tok"}],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"accountId":"ACC-001","ownerId":"usr-A","balance":5000}'},
                },
            },
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/v1/accounts/ACC-002",
                    "headers": [{"name": "Authorization", "value": "Bearer tok"}],
                    "queryString": [],
                    "postData": None,
                },
                "response": {
                    "status": 200,
                    "headers": [],
                    "content": {"text": '{"accountId":"ACC-002","ownerId":"usr-B","balance":12000}'},
                },
            },
        ]
    }
})

_NO_AUTH_HAR = json.dumps({
    "log": {
        "entries": [
            {
                "request": {
                    "method": "GET",
                    "url": "https://cdn.example.com/logo.png",
                    "headers": [],
                    "queryString": [],
                    "postData": None,
                },
                "response": {"status": 200, "headers": [], "content": {"text": ""}},
            }
        ]
    }
})


def _make_index_from(har_json: str) -> FactIndex:
    extractor = HarExtractor()
    artifact = extractor.extract(har_json)
    return FactIndex.build(artifact)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBuild:
    def test_build_returns_fact_index(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert isinstance(fi, FactIndex)

    def test_entries_are_indexed_by_id(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert 1 in fi.entries

    def test_two_entries_both_indexed(self):
        fi = _make_index_from(_TWO_ENTRY_HAR)
        assert 1 in fi.entries
        assert 2 in fi.entries

    def test_host_set_populated(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert any("example.com" in h for h in fi.all_host_set)


class TestHasEntry:
    def test_present_entry_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.has_entry(1) is True

    def test_absent_entry_not_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.has_entry(99) is False


class TestEntryContains:
    def test_verbatim_substring_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        # "Method: GET" should appear in the condensed entry text
        assert fi.entry_contains(1, "Method: GET") is True

    def test_url_fragment_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_contains(1, "v1/users") is True

    def test_response_body_fragment_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_contains(1, "alice@example.com") is True

    def test_fabricated_string_not_found(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_contains(1, "COMPLETELY_FABRICATED_XYZ_12345") is False

    def test_nonexistent_entry_returns_false(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_contains(99, "Method: GET") is False


class TestEntryStatus:
    def test_200_status_returned(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_status(1) == 200

    def test_nonexistent_entry_returns_none(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_status(99) is None


class TestAuthPresence:
    def test_bearer_token_present(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        assert fi.entry_has_auth(1) is True

    def test_no_auth_header(self):
        fi = _make_index_from(_NO_AUTH_HAR)
        assert fi.entry_has_auth(1) is False


class TestCrossCustomerDetection:
    def test_two_owners_detected(self):
        fi = _make_index_from(_TWO_ENTRY_HAR)
        # usr-A and usr-B are two distinct ownerId values → cross-customer
        assert fi.cross_customer_confirmed is True

    def test_single_owner_not_cross_customer(self):
        fi = _make_index_from(_SINGLE_ENTRY_HAR)
        # Only one entry — can't be cross-customer
        assert fi.cross_customer_confirmed is False
