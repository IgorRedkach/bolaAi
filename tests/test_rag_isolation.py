"""Tests for bola_ai.rag.rag_isolation — session source filter and contamination detection."""
from __future__ import annotations

import pytest

from bola_ai.rag.rag_isolation import (
    KNOWLEDGE_SOURCES,
    CONTAMINATING_DOCS,
    build_session_source_filter,
)


class TestBuildSessionSourceFilter:
    def test_canonical_sources_always_included(self):
        result = build_session_source_filter([])
        for src in KNOWLEDGE_SOURCES:
            assert src in result

    def test_user_doc_added_when_clean(self):
        result = build_session_source_filter(["user_report.pdf"])
        assert "user_report.pdf" in result

    def test_contaminating_doc_excluded(self):
        for contaminator in CONTAMINATING_DOCS:
            result = build_session_source_filter([contaminator])
            assert contaminator not in result, (
                f"Contaminating doc {contaminator!r} should be excluded but was included"
            )

    def test_contaminating_doc_excluded_by_basename(self):
        result = build_session_source_filter(["/some/path/context.txt"])
        assert "/some/path/context.txt" not in result

    def test_mix_of_clean_and_contaminating(self):
        user_docs = ["my_api.har", "doc_adversarial_graphql.md", "another_clean.pdf"]
        result = build_session_source_filter(user_docs)
        assert "my_api.har" in result
        assert "doc_adversarial_graphql.md" not in result
        assert "another_clean.pdf" in result

    def test_empty_input_returns_canonical_only(self):
        result = build_session_source_filter([])
        assert set(result) == KNOWLEDGE_SOURCES

    def test_returns_list(self):
        result = build_session_source_filter([])
        assert isinstance(result, list)

    def test_no_duplicates_in_result(self):
        # Even if user provides a canonical source explicitly, no duplicate
        canonical = next(iter(KNOWLEDGE_SOURCES))
        result = build_session_source_filter([canonical])
        assert result.count(canonical) == len([x for x in result if x == canonical])


class TestConstants:
    def test_knowledge_sources_nonempty(self):
        assert len(KNOWLEDGE_SOURCES) > 0

    def test_contaminating_docs_nonempty(self):
        assert len(CONTAMINATING_DOCS) > 0

    def test_no_overlap_between_canonical_and_contaminating(self):
        overlap = KNOWLEDGE_SOURCES & CONTAMINATING_DOCS
        assert overlap == frozenset(), f"Overlap found: {overlap}"
