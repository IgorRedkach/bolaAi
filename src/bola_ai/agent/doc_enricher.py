"""DocEnricher — cross-validates HAR findings against additional ingested documents.

After the PRISM-HAR pipeline produces ValidatedFindings, this step searches the
RAG store for non-HAR documents (OpenAPI specs, schemas, code docs, etc.) that
corroborate or contradict each finding.  No LLM is involved in the mechanical
search pass; an optional LLM classification call is made only when the
corroboration relationship is ambiguous.

The enrichment result carries:
- doc_evidences: list of retrieved chunks classified by relation
- enriched_confidence: adjusted from the raw finding if corroborated/contradicted
- enrichment_note: short summary of what the docs add or contradict
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bola_ai.agent.validator import ValidatedFinding
from bola_ai.rag.store import DocStore
from bola_ai.logging_config import get_logger

logger = get_logger("doc_enricher")

# Pattern labels used to build targeted RAG queries
_PATTERN_QUERY_HINTS: dict[str, str] = {
    "1.1":  "object ID in path authorization ownership check",
    "1.2":  "related linked resource authorization",
    "1.3":  "bulk list endpoint authorization filter",
    "1.4":  "third-party storage API authorization",
    "1.5":  "multi-tenant cross-tenant isolation",
    "1.6":  "write operation ownership check",
    "1.7":  "nested resource parent authorization",
    "1.8":  "predictable sequential ID enumeration",
    "1.9":  "batch bulk lookup authorization",
    "1.10": "cross-service identity propagation tenant context",
    "1.11": "cache key authorization user dimension",
    "1.12": "mass assignment object field ownership role",
    "1.13": "IoT SCADA device ID node authorization",
    "10.1": "ID swap request parameter manipulation",
    "10.2": "parameter escalation session scope",
    "10.3": "temporary ID hijacking",
    "10.4": "lifecycle state bypass workflow",
    "10.5": "draft unpublished resource access",
    "10.6": "subscription webhook hijacking",
}

# Keywords whose presence in a retrieved chunk suggests corroboration
_CORROBORATE_KEYWORDS = frozenset({
    "no authorization", "missing auth", "without auth check",
    "does not verify", "does not validate ownership", "no ownership",
    "publicly accessible", "no access control", "unauthenticated",
    "any user", "skip", "bypass", "no tenant check",
    "not verified", "not validated", "shared across",
})

# Keywords whose presence suggests the doc contradicts the finding (i.e. control exists)
_CONTRADICT_KEYWORDS = frozenset({
    "authorization required", "ownership verified", "access control enforced",
    "requires authentication", "tenant scoped", "user scoped",
    "role required", "permission required", "validates ownership",
    "checks ownership", "enforces authorization", "403 if", "401 if",
    "must be owner", "must belong to",
})


@dataclass
class DocEvidence:
    source: str
    chunk: str
    relation: str        # "corroborates" | "contradicts" | "context"
    confidence: str      # "high" | "medium" | "low"
    excerpt: str = ""    # short snippet for report display


@dataclass
class EnrichedFinding:
    validated: ValidatedFinding
    doc_evidences: list[DocEvidence] = field(default_factory=list)
    enriched_confidence: str = ""     # may be upgraded/downgraded; empty = unchanged
    enrichment_note: str = ""


class DocEnricher:
    """Cross-validates validated HAR findings against additional documents in the store.

    Usage::

        enricher = DocEnricher(store, non_har_sources=["openapi.yaml", "schema.md"])
        enriched = enricher.enrich_all(validation_result.accepted)
    """

    def __init__(
        self,
        store: DocStore,
        *,
        non_har_sources: Optional[list[str]] = None,
        n_results_per_finding: int = 4,
        use_llm_classification: bool = False,
        model: Optional[str] = None,
    ) -> None:
        self._store = store
        self._non_har_sources = non_har_sources or []
        self._n = n_results_per_finding
        self._use_llm = use_llm_classification
        self._model = model

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def enrich_all(self, findings: list[ValidatedFinding]) -> list[EnrichedFinding]:
        """Enrich every finding in the list.  Returns a 1-to-1 list."""
        if not self._non_har_sources:
            logger.debug("DocEnricher: no non-HAR sources available; skipping enrichment")
            return [EnrichedFinding(validated=vf) for vf in findings]

        results: list[EnrichedFinding] = []
        for vf in findings:
            enriched = self._enrich_one(vf)
            results.append(enriched)
        logger.info(
            "DocEnricher: enriched %d findings against %d doc sources",
            len(results), len(self._non_har_sources),
        )
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich_one(self, vf: ValidatedFinding) -> EnrichedFinding:
        raw = vf.raw
        query = self._build_query(raw.pattern_id, raw.attack_delta, raw.evidence_quote)

        chunks = self._store.search(
            query,
            n_results=self._n,
            source_filter=self._non_har_sources,
        )

        evidences: list[DocEvidence] = []
        for chunk in chunks:
            content = chunk.get("content", "")
            source = chunk.get("source", "unknown")
            relation, confidence = self._classify_relation(content)
            evidences.append(DocEvidence(
                source=source,
                chunk=content,
                relation=relation,
                confidence=confidence,
                excerpt=content[:200].strip(),
            ))

        enriched_confidence, note = self._derive_confidence_note(
            vf.raw.confidence, evidences
        )

        return EnrichedFinding(
            validated=vf,
            doc_evidences=evidences,
            enriched_confidence=enriched_confidence,
            enrichment_note=note,
        )

    def _build_query(self, pattern_id: str, attack_delta: str, evidence_quote: str) -> str:
        hint = _PATTERN_QUERY_HINTS.get(pattern_id, "authorization access control")
        # Pull out the key path/endpoint from attack_delta for targeted retrieval
        path_match = re.search(r"/[a-zA-Z0-9_\-/{}]{3,}", attack_delta or "")
        path_part = path_match.group(0) if path_match else ""
        query_parts = [hint]
        if path_part:
            query_parts.append(path_part)
        if evidence_quote:
            query_parts.append(evidence_quote[:80])
        return " ".join(query_parts)

    def _classify_relation(self, text: str) -> tuple[str, str]:
        """Classify the relation of a doc chunk to a finding.

        Returns (relation, confidence) where relation is one of:
        'corroborates', 'contradicts', 'context'.
        """
        lower = text.lower()
        corr_hits = sum(1 for kw in _CORROBORATE_KEYWORDS if kw in lower)
        contr_hits = sum(1 for kw in _CONTRADICT_KEYWORDS if kw in lower)

        if corr_hits == 0 and contr_hits == 0:
            return "context", "low"

        if corr_hits >= contr_hits:
            confidence = "high" if corr_hits >= 2 else "medium"
            return "corroborates", confidence

        confidence = "high" if contr_hits >= 2 else "medium"
        return "contradicts", confidence

    def _derive_confidence_note(
        self,
        original_confidence: str,
        evidences: list[DocEvidence],
    ) -> tuple[str, str]:
        """Derive adjusted confidence and a short note from the evidence list."""
        if not evidences:
            return "", ""

        corr = [e for e in evidences if e.relation == "corroborates"]
        contr = [e for e in evidences if e.relation == "contradicts"]

        notes: list[str] = []

        if corr:
            src_list = ", ".join(sorted({e.source for e in corr})[:2])
            notes.append(f"Corroborated by: {src_list}.")

        if contr:
            src_list = ", ".join(sorted({e.source for e in contr})[:2])
            notes.append(f"Possible control documented in: {src_list} — verify if enforced at runtime.")

        enriched_confidence = original_confidence
        if corr and not contr:
            if original_confidence == "low":
                enriched_confidence = "medium"
            elif original_confidence == "medium":
                enriched_confidence = "high"
        elif contr and not corr:
            if original_confidence == "high":
                enriched_confidence = "medium"

        return enriched_confidence, " ".join(notes)
