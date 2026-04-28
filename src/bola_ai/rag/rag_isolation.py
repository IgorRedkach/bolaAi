"""RAG isolation for PRISM-HAR pipeline.

Problem: fixture/benchmark docs in shared_docs/ contaminate every analysis by being
auto-ingested into the shared ChromaDB collection at container start.

Solution: a whitelist of allowed knowledge sources + a session-scoped source filter
that restricts RAG retrieval to only the user's uploaded docs + canonical knowledge.

This module is used by runner.py to build the source_filter for every analysis call.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bola_ai.rag.store import DocStore

logger = logging.getLogger(__name__)

# Canonical knowledge sources — always allowed in RAG regardless of session
KNOWLEDGE_SOURCES: frozenset[str] = frozenset([
    "bola_patterns.md",
    "ai_teacher_bola_quality_patterns.md",
    "phase1_small_model_guidelines.md",
])

# Fixture/adversarial documents that must NOT contaminate production analysis.
# These documents exist for testing and benchmarking only.
# At runtime they should never be ingested into the shared collection.
CONTAMINATING_DOCS: frozenset[str] = frozenset([
    "doc_benchmark_salesforce_har_like_20260330.md",
    "doc_adversarial_salesforce.md",
    "doc_adversarial_graphql.md",
    "context.txt",
    "doc_crm_contacts.md",
])


def build_session_source_filter(user_doc_sources: list[str]) -> list[str]:
    """Build a source filter that includes only:

    1. Canonical knowledge sources
    2. User-uploaded docs for this session

    Excludes any source in CONTAMINATING_DOCS.
    Returns the merged list that can be passed directly as source_filter to DocStore.search().
    """
    allowed: list[str] = list(KNOWLEDGE_SOURCES)
    for src in user_doc_sources:
        basename = Path(src).name
        if basename not in CONTAMINATING_DOCS:
            allowed.append(src)
        else:
            logger.warning(
                "rag_isolation: dropping contaminating source %r from session filter", src
            )
    return allowed


def get_contaminating_docs_in_store(store: "DocStore") -> list[str]:
    """Scan the ChromaDB collection and return any source names that are in CONTAMINATING_DOCS.

    Used at startup to warn operators that the store contains fixture documents that could
    bias production analysis results.
    """
    found: list[str] = []
    try:
        # Access the underlying collection to list all unique sources
        collection = store._collection  # type: ignore[attr-defined]
        result = collection.get(include=["metadatas"])
        metadatas = result.get("metadatas") or []
        seen: set[str] = set()
        for meta in metadatas:
            src = (meta or {}).get("source", "")
            if not src or src in seen:
                continue
            seen.add(src)
            if Path(src).name in CONTAMINATING_DOCS:
                found.append(src)
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("get_contaminating_docs_in_store: error listing sources: %s", exc)
    return found


def warn_if_contaminated(store: "DocStore") -> None:
    """Log a warning for each contaminating document found in the store."""
    contaminated = get_contaminating_docs_in_store(store)
    for src in contaminated:
        logger.warning(
            "RAG CONTAMINATION WARNING: fixture document %r is present in the shared "
            "ChromaDB collection. This will bias analysis results. Remove it from the "
            "ingest pipeline or delete it from the collection.",
            src,
        )
