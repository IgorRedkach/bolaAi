"""HAR-specialist analyzer — two-pass LLM analysis for BOLA findings.

Pass 1 (FACT PASS): Identify which HAR entry IDs are security-relevant
and which patterns may be present. Low token budget.

Pass 2 (ANALYSIS PASS): For each flagged entry, produce a structured JSON
finding. Grammar-constrained to ensure valid JSON output (grammar is passed
as an Ollama option when the bola-har specialist model is available).

Both passes use the bola-har specialist model when available; fall back to the
base OLLAMA_MODEL otherwise.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from bola_ai.agent.llm import chat, generate
from bola_ai.logging_config import get_logger
from bola_ai.rag.har_extractor import StructuredArtifact

logger = get_logger("har_analyzer")

HAR_SPECIALIST_MODEL = os.environ.get("BOLA_HAR_MODEL", "bola-har")
HAR_PASS2_NUM_PREDICT = int(os.environ.get("BOLA_HAR_NUM_PREDICT", "2048"))
HAR_PASS2_NUM_CTX = int(os.environ.get("BOLA_HAR_NUM_CTX", "8192"))

# Instruction text that mirrors the training data instruction field exactly.
_TRAINING_INSTRUCTION = (
    "You are a BOLA/authorization security analyzer. Analyze the following HAR entries "
    "for authorization vulnerabilities. Output a JSON array of findings. Reference only "
    "entry IDs from the entries provided. For every finding, evidence_quote must be a "
    "verbatim substring of the corresponding entry text."
)

# Minimal GBNF grammar to constrain output to a valid JSON array of findings.
_FINDINGS_GRAMMAR = r"""
root   ::= "[" ws ( finding ( "," ws finding )* )? "]"
finding ::= "{" ws
  "\"entry_id\""      ws ":" ws number   ws ","  ws
  "\"pattern_id\""    ws ":" ws string   ws ","  ws
  "\"pattern_name\""  ws ":" ws string   ws ","  ws
  "\"evidence_quote\""ws ":" ws string   ws ","  ws
  "\"attack_delta\""  ws ":" ws string   ws ","  ws
  "\"poc_entry_id\""  ws ":" ws number   ws ","  ws
  "\"confidence\""    ws ":" ws conf     ws ","  ws
  "\"note\""          ws ":" ws string
ws "}"
conf   ::= "\"high\"" | "\"medium\"" | "\"low\""
number ::= [0-9]+
string ::= "\"" char* "\""
char   ::= [^"\\] | "\\" ["\\/bfnrt]
ws     ::= [ \t\n]*
"""


@dataclass
class RawFinding:
    entry_id: int
    pattern_id: str
    pattern_name: str
    evidence_quote: str
    attack_delta: str
    poc_entry_id: int
    confidence: str
    note: str


@dataclass
class HarAnalysisResult:
    findings: list[RawFinding] = field(default_factory=list)
    model_used: str = ""
    error: Optional[str] = None


class HarAnalyzer:
    """Sends the condensed HAR entries text to the LLM and parses the response."""

    def __init__(self, *, use_grammar: bool = True):
        self._use_grammar = use_grammar

    def analyze(
        self,
        artifact: StructuredArtifact,
        *,
        model: Optional[str] = None,
    ) -> HarAnalysisResult:
        effective_model = model or HAR_SPECIALIST_MODEL
        entries_text = artifact.to_entries_list_text()

        # Build the exact prompt format used during training:
        # ### Instruction\n{instruction}\n\n### Context\n{context}\n\n### Response\n
        prompt = (
            f"### Instruction\n{_TRAINING_INSTRUCTION}\n\n"
            f"### Context\n{entries_text}\n\n"
            f"### Response\n"
        )

        grammar = _FINDINGS_GRAMMAR if self._use_grammar else None
        try:
            raw = generate(
                prompt,
                model=effective_model,
                grammar=grammar,
                num_predict=HAR_PASS2_NUM_PREDICT,
                num_ctx=HAR_PASS2_NUM_CTX,
            )
        except Exception as exc:
            logger.warning("bola-har model unavailable (%s); retrying with base model", exc)
            try:
                from bola_ai.config import OLLAMA_MODEL
                raw = generate(
                    prompt,
                    model=OLLAMA_MODEL,
                    num_predict=HAR_PASS2_NUM_PREDICT,
                    num_ctx=HAR_PASS2_NUM_CTX,
                )
                effective_model = OLLAMA_MODEL
            except Exception as exc2:
                return HarAnalysisResult(error=str(exc2))

        return self._parse(raw, effective_model)

    def _parse(self, raw: str, model_used: str) -> HarAnalysisResult:
        text = raw.strip()
        # Attempt to extract the JSON array from the response even if
        # the model emitted surrounding prose.
        # Use raw_decode from the first "[" to avoid issues when the model
        # emits trailing content after the array (e.g. "[]↵explanation...").
        start = text.find("[")
        if start == -1:
            logger.warning("No JSON array found in model output: %r", text[:200])
            return HarAnalysisResult(model_used=model_used,
                                     error="no JSON array in output")
        try:
            decoder = json.JSONDecoder()
            items, _ = decoder.raw_decode(text, start)
        except json.JSONDecodeError as exc:
            # Fallback: try to extract up to the matching closing bracket
            end = text.rfind("]") + 1
            try:
                items = json.loads(text[start:end])
            except json.JSONDecodeError:
                return HarAnalysisResult(model_used=model_used,
                                         error=f"JSON parse error: {exc}")
        if not isinstance(items, list):
            return HarAnalysisResult(model_used=model_used,
                                     error="top-level is not a list")

        findings: list[RawFinding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                findings.append(RawFinding(
                    entry_id=int(item["entry_id"]),
                    pattern_id=str(item["pattern_id"]),
                    pattern_name=str(item["pattern_name"]),
                    evidence_quote=str(item["evidence_quote"]),
                    attack_delta=str(item["attack_delta"]),
                    poc_entry_id=int(item.get("poc_entry_id", item["entry_id"])),
                    confidence=str(item.get("confidence", "medium")),
                    note=str(item.get("note", "")),
                ))
            except (KeyError, ValueError, TypeError) as exc:
                logger.debug("Skipping malformed finding: %s — %s", item, exc)

        return HarAnalysisResult(findings=findings, model_used=model_used)
