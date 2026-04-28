"""Validates RawFindings from the LLM against the deterministic FactIndex.

Every validation check is purely mechanical — no LLM involved. A finding
passes only when ALL of the following hold:

1. The entry_id exists in the HAR entries list.
2. The evidence_quote is a verbatim substring of that entry's condensed text.
3. The poc_entry_id (if different from entry_id) also exists in the entry list.
4. The pattern_id is in the set of recognized patterns.
5. The confidence value is one of: high, medium, low.

Findings that fail any check are quarantined in the `rejected` list with a
reason so the report can surface them as un-verified instead of hiding them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from bola_ai.agent.har_analyzer import RawFinding
from bola_ai.rag.fact_index import FactIndex
from bola_ai.logging_config import get_logger

logger = get_logger("validator")

_KNOWN_PATTERNS: frozenset[str] = frozenset({
    "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9",
    "1.10", "1.11", "1.12", "1.13",
    "10.1", "10.2", "10.3", "10.4", "10.5", "10.6",
})

_VALID_CONFIDENCE: frozenset[str] = frozenset({"high", "medium", "low"})


@dataclass
class ValidatedFinding:
    raw: RawFinding
    passed: bool
    failure_reason: Optional[str] = None


@dataclass
class ValidationResult:
    accepted: list[ValidatedFinding] = field(default_factory=list)
    rejected: list[ValidatedFinding] = field(default_factory=list)

    @property
    def all(self) -> list[ValidatedFinding]:
        return self.accepted + self.rejected


class FindingValidator:
    """Validates all findings from HarAnalysisResult against a FactIndex."""

    def validate_all(
        self,
        findings: list[RawFinding],
        fact_index: FactIndex,
    ) -> ValidationResult:
        result = ValidationResult()
        for raw in findings:
            vf = self.validate_one(raw, fact_index)
            if vf.passed:
                result.accepted.append(vf)
            else:
                result.rejected.append(vf)
                logger.debug(
                    "REJECTED finding entry_id=%s pattern=%s reason=%s",
                    raw.entry_id, raw.pattern_id, vf.failure_reason,
                )
        return result

    def validate_one(
        self,
        raw: RawFinding,
        fact_index: FactIndex,
    ) -> ValidatedFinding:
        reason = self._check(raw, fact_index)
        return ValidatedFinding(raw=raw, passed=(reason is None), failure_reason=reason)

    def _check(
        self,
        raw: RawFinding,
        fi: FactIndex,
    ) -> Optional[str]:
        # Check 1: entry exists
        if not fi.has_entry(raw.entry_id):
            return f"entry_id {raw.entry_id} not in HAR entries list"

        # Check 2: evidence_quote is verbatim substring
        if raw.evidence_quote and not fi.entry_contains(raw.entry_id, raw.evidence_quote):
            return (
                f"evidence_quote not found verbatim in entry {raw.entry_id}: "
                f"{raw.evidence_quote[:80]!r}"
            )

        # Check 3: poc_entry_id exists (when different from entry_id)
        if raw.poc_entry_id != raw.entry_id and not fi.has_entry(raw.poc_entry_id):
            return f"poc_entry_id {raw.poc_entry_id} not in HAR entries list"

        # Check 4: known pattern
        if raw.pattern_id not in _KNOWN_PATTERNS:
            return f"unknown pattern_id {raw.pattern_id!r}"

        # Check 5: confidence value
        if raw.confidence not in _VALID_CONFIDENCE:
            return f"invalid confidence value {raw.confidence!r}"

        # Check 6: evidence_quote must be non-empty
        if not raw.evidence_quote.strip():
            return "evidence_quote is empty"

        return None
