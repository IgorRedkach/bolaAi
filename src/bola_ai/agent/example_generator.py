"""ExampleGenerator — produces typed verification examples for security findings.

This is a separate pipeline step, intentionally decoupled from the core BOLA
analysis, so it can evolve independently:
- Prompts are isolated in prompts_examples.py.
- It uses bola-analyzer today; can be swapped to a specialist model (bola-examples)
  once separate training data is available.
- One EnrichedFinding → one VerificationExample (or empty if not enough evidence).

The step runs AFTER DocEnricher; it receives EnrichedFinding objects which carry
richer context (doc_evidences, enriched_confidence, enrichment_note).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from bola_ai.agent.doc_enricher import EnrichedFinding
from bola_ai.agent.prompts_examples import (
    EXAMPLES_SYSTEM_PROMPT,
    detect_api_type,
    select_prompt,
)
from bola_ai.logging_config import get_logger
from bola_ai.rag.har_extractor import StructuredArtifact, HarEntry

logger = get_logger("example_generator")

# Override env var to point at a future specialist model
import os
_EXAMPLES_MODEL_ENV = os.environ.get("BOLA_AI_EXAMPLES_MODEL", "")


@dataclass
class VerificationExample:
    pattern_id: str
    api_type: str           # "graphql" | "rest" | "soql" | "mixed"
    endpoint: str
    method: str
    examples: list[str]     # each entry is a copy-pasteable block (curl / gql / soql)
    generation_note: str = ""


@dataclass
class ExampleGenerationResult:
    examples: list[VerificationExample] = field(default_factory=list)
    api_type: str = "rest"
    model_used: str = ""
    skipped_count: int = 0


class ExampleGenerator:
    """Generates typed verification examples for a list of EnrichedFindings.

    Usage::

        gen = ExampleGenerator(artifact=artifact)
        result = gen.generate(enriched_findings)
        for ex in result.examples:
            print(ex.endpoint, ex.examples)
    """

    def __init__(
        self,
        artifact: Optional[StructuredArtifact] = None,
        *,
        model: Optional[str] = None,
        num_predict: int = 512,
        context_str: str = "",
    ) -> None:
        self._artifact = artifact
        self._model = model or _EXAMPLES_MODEL_ENV or None
        self._num_predict = num_predict
        self._context_str = context_str
        self._api_type: Optional[str] = None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate(self, enriched: list[EnrichedFinding]) -> ExampleGenerationResult:
        if not enriched:
            return ExampleGenerationResult()

        api_type = self._detect_api_type()
        examples: list[VerificationExample] = []
        skipped = 0

        for ef in enriched:
            ex = self._generate_one(ef, api_type)
            if ex is None:
                skipped += 1
            else:
                examples.append(ex)

        model_used = self._model or "bola-analyzer"
        logger.info(
            "ExampleGenerator: %d examples generated, %d skipped (api_type=%s, model=%s)",
            len(examples), skipped, api_type, model_used,
        )
        return ExampleGenerationResult(
            examples=examples,
            api_type=api_type,
            model_used=model_used,
            skipped_count=skipped,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_api_type(self) -> str:
        if self._api_type is not None:
            return self._api_type

        context = self._context_str
        if self._artifact:
            # Build a representative context string from the artifact entries
            sample_entries = self._artifact.entries[:20]
            context += " ".join(
                f"{e.method} {e.url}" for e in sample_entries
            )

        self._api_type = detect_api_type(context)
        return self._api_type

    def _generate_one(
        self,
        ef: EnrichedFinding,
        api_type: str,
    ) -> Optional[VerificationExample]:
        raw = ef.validated.raw
        entry = self._find_entry(raw.poc_entry_id) or self._find_entry(raw.entry_id)

        endpoint = ""
        method = "GET"
        if entry:
            endpoint = self._path_from_url(entry.url)
            method = entry.method or "GET"

        # Build evidence string (HAR evidence + doc context if available)
        evidence_parts = [raw.evidence_quote]
        for de in ef.doc_evidences[:2]:
            evidence_parts.append(de.excerpt)
        evidence = " | ".join(p for p in evidence_parts if p)

        if not endpoint and not evidence:
            logger.debug(
                "ExampleGenerator: skipping finding pattern=%s — no endpoint or evidence",
                raw.pattern_id,
            )
            return None

        user_prompt = select_prompt(
            api_type,
            pattern_id=raw.pattern_id,
            pattern_name=raw.pattern_name,
            evidence=evidence,
            attack_delta=raw.attack_delta,
            endpoint=endpoint or "/api/resource/{id}",
            method=method,
        )

        raw_output = self._call_llm(user_prompt)

        if not raw_output or raw_output.startswith("NO_EXAMPLE"):
            logger.debug(
                "ExampleGenerator: no example produced for pattern=%s: %s",
                raw.pattern_id, raw_output[:100] if raw_output else "",
            )
            return None

        example_blocks = self._extract_blocks(raw_output)
        if not example_blocks:
            example_blocks = [raw_output.strip()]

        note = ef.enrichment_note or ""
        if ef.enriched_confidence and ef.enriched_confidence != raw.confidence:
            note = f"Confidence adjusted to {ef.enriched_confidence}. " + note

        return VerificationExample(
            pattern_id=raw.pattern_id,
            api_type=api_type,
            endpoint=endpoint,
            method=method,
            examples=example_blocks,
            generation_note=note.strip(),
        )

    def _find_entry(self, entry_id: int) -> Optional[HarEntry]:
        if self._artifact is None:
            return None
        for e in self._artifact.entries:
            if e.id == entry_id:
                return e
        return None

    def _path_from_url(self, url: str) -> str:
        if not url:
            return ""
        try:
            from urllib.parse import urlparse
            return urlparse(url).path or ""
        except Exception:
            return ""

    def _call_llm(self, user_prompt: str) -> str:
        try:
            from bola_ai.agent.llm import chat
            messages = [
                {"role": "system", "content": EXAMPLES_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]
            return chat(
                messages,
                model=self._model or None,
                num_predict=self._num_predict,
            )
        except Exception as exc:
            logger.warning("ExampleGenerator LLM call failed: %s", exc)
            return ""

    def _extract_blocks(self, text: str) -> list[str]:
        """Extract fenced code blocks (```...```) from LLM output."""
        blocks = re.findall(r"```[a-zA-Z]*\n([\s\S]*?)```", text)
        if blocks:
            return [b.strip() for b in blocks if b.strip()]
        # Fallback: return the whole text as one block
        return [text.strip()]
