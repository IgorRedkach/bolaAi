# PRISM-HAR Refactoring Plan
**Date:** 2026-04-24  
**Status:** Active  

This document specifies every code change needed to implement the PRISM-HAR pipeline.
A fresh agent can execute this plan in order without additional context.

---

## Context

The current system is a single-pass RAG+LLM analyzer in `src/bola_ai/agent/runner.py`.
PRISM-HAR adds a HAR-specific two-pass pipeline that intercepts HAR inputs before the
general-purpose flow, extracts structured facts deterministically, runs a fine-tuned
specialist model with grammar-constrained output, validates findings, and renders reports
deterministically. The existing flow remains unchanged for non-HAR inputs.

---

## Design Principles

1. **No breaking changes.** The existing `run_analysis` / `analyze_for_bola` API is preserved.
2. **HAR detection is the gate.** If the ingested content is detected as HAR JSON, the new pipeline
   runs. Otherwise, the existing runner handles it unchanged.
3. **All new modules are independently unit-testable.** No module imports from another new module
   except through defined interfaces.
4. **Grammar constraints are applied at inference.** The fine-tuned `bola-har` model always runs
   with the GBNF grammar for Finding JSON to prevent structurally invalid output.
5. **Fallback to existing pipeline.** If the HAR extractor fails or the structured pipeline errors,
   fall back to the existing `run_analysis` path and log the failure.

---

## New Files to Create

### 1. `src/bola_ai/rag/har_extractor.py`

**Purpose**: Deterministic HAR JSON parser. Takes raw HAR JSON text, returns `StructuredArtifact`.
No LLM involvement. This is the P3 extractor applied to HAR format.

```python
"""Deterministic HAR parser for PRISM-HAR pipeline.

Extracts security-relevant structure from HAR (HTTP Archive) JSON without any LLM.
Returns StructuredArtifact containing hosts, entries with request/response details,
auth context, and ID patterns.

Usage:
    extractor = HarExtractor()
    artifact = extractor.extract(raw_har_text)  # raw_har_text is the HAR file content
    if artifact is None:
        # Not a HAR, fall back to general pipeline
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse


@dataclass
class HarEntry:
    """Security-relevant fields from one HAR log entry."""
    id: int                                  # 1-indexed position in the HAR
    method: str                              # GET, POST, PUT, PATCH, DELETE, etc.
    url: str                                 # full URL
    host: str                                # extracted hostname
    path: str                                # URL path only
    query_string: dict[str, list[str]]       # parsed query params
    request_headers: dict[str, str]          # normalized header name → value (auth-relevant only)
    body_text: Optional[str]                 # raw body text (may be URL-encoded or JSON)
    body_params: dict[str, str]              # parsed if URL-encoded
    body_json: Optional[dict]               # parsed if application/json
    response_status: int
    response_headers: dict[str, str]         # Cache-Control, Vary, ETag, etc.
    response_body_excerpt: Optional[str]     # first 400 chars of response body
    content_type: Optional[str]              # request Content-Type
    # Derived fields
    path_id_segments: list[str]             # segments that look like IDs (int, UUID, custom)
    is_auth_flow: bool                       # True if this looks like OAuth/login/token
    is_analytics: bool                       # True if this looks like telemetry/tracking
    is_static_resource: bool                 # True if .css/.js/.png/etc.
    is_internal_endpoint: bool               # True if /health, /metrics, /version, OPTIONS


@dataclass
class AuthContext:
    """Auth context extracted from HAR."""
    token_type: Optional[str]                # Bearer, Basic, ApiKey
    bearer_prefix: Optional[str]             # First 40 chars of Bearer token (truncated)
    cookie_names: list[str]                  # Auth-relevant cookie names


@dataclass
class StructuredArtifact:
    """Fully structured representation of a HAR file for the analyzer."""
    artifact_type: str = "har"
    hosts: list[str] = field(default_factory=list)
    entries: list[HarEntry] = field(default_factory=list)
    auth_context: Optional[AuthContext] = None
    # Derived signals
    has_sequential_int_ids: bool = False     # True if consecutive integers seen in paths
    has_tenant_params: bool = False          # True if tenantId/orgId seen
    has_batch_endpoints: bool = False        # True if array of IDs in any request body
    entry_count: int = 0
    security_relevant_entry_ids: list[int] = field(default_factory=list)  # non-noise entry IDs

    def to_entries_list_text(self) -> str:
        """Render structured entries as the ENTRIES LIST text the analyzer model receives."""
        ...  # implementation renders condensed human-readable entries list


class HarExtractor:
    """Deterministic HAR → StructuredArtifact extractor."""

    # Headers to keep (security-relevant)
    KEEP_REQUEST_HEADERS = {
        "authorization", "cookie", "x-tenant-id", "x-org-id", "x-organization-id",
        "x-workspace-id", "x-client-id", "x-user-id", "x-forwarded-for",
        "x-api-key", "x-auth-token", "content-type",
    }
    KEEP_RESPONSE_HEADERS = {
        "cache-control", "vary", "etag", "x-frame-options", "content-type",
        "set-cookie", "www-authenticate",
    }

    # Patterns for ID detection in path segments
    INT_ID_PATTERN = re.compile(r'^\d{4,}$')           # 4+ digit integers
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I
    )
    SF_ID_PATTERN = re.compile(r'^[0-9A-Za-z]{15}([0-9A-Za-z]{3})?$')  # Salesforce 15/18
    CUSTOM_ID_PATTERN = re.compile(r'^[A-Z]+-\d{3,}$')  # e.g. INV-2024-0042, CASE-88291

    # Auth flow detection
    AUTH_PATH_PATTERNS = re.compile(
        r'/(oauth|auth|login|token|refresh|connect|authorize|logout|sso|saml)', re.I
    )
    AUTH_BODY_KEYS = {'grant_type', 'client_id', 'refresh_token', 'code', 'client_secret'}

    # Analytics detection
    ANALYTICS_HOST_PATTERNS = re.compile(
        r'(analytics|telemetry|tracking|metrics|datadog|amplitude|mixpanel|'
        r'segment\.io|hotjar|fullstory|rum\.|beacon)', re.I
    )
    ANALYTICS_PATH_PATTERNS = re.compile(
        r'/(collect|track|event|beacon|ping|rum|log|ingest|metric)', re.I
    )
    STATIC_EXTENSIONS = re.compile(
        r'\.(css|js|woff2?|ttf|eot|png|jpg|jpeg|gif|ico|svg|map|webp)(\?|$)', re.I
    )
    INTERNAL_PATH_PATTERNS = re.compile(
        r'/(health|status|version|metrics|favicon|ping|__webpack|OPTIONS)', re.I
    )

    def is_har(self, text: str) -> bool:
        """Quick check: is this text a HAR JSON file?"""
        ...

    def extract(self, raw_text: str) -> Optional[StructuredArtifact]:
        """Parse raw HAR text → StructuredArtifact. Returns None if not a valid HAR."""
        ...

    def _parse_entry(self, idx: int, entry: dict) -> HarEntry:
        """Parse one HAR log entry into HarEntry."""
        ...

    def _classify_entry(self, entry: HarEntry) -> HarEntry:
        """Classify entry as auth/analytics/static/internal/security-relevant."""
        ...

    def _extract_auth_context(self, entries: list[HarEntry]) -> AuthContext:
        """Extract auth context from the most common auth header across entries."""
        ...

    def _detect_sequential_ids(self, entries: list[HarEntry]) -> bool:
        """Check if any path has consecutive integer IDs across entries."""
        ...
```

**Implementation notes**:
- `is_har` checks for `"log"` key with `"entries"` array in the top-level JSON
- `extract` calls `json.loads`, walks `log.entries`, calls `_parse_entry` for each
- `_classify_entry` applies AUTH/ANALYTICS/STATIC/INTERNAL patterns to mark noise
- `security_relevant_entry_ids` = entries where `is_auth_flow = is_analytics = is_static_resource = is_internal_endpoint = False`
- `to_entries_list_text` renders the condensed format from DATA_GENERATION_STANDARDS.md §2.1

---

### 2. `src/bola_ai/rag/fact_index.py`

**Purpose**: Build an in-memory index of all observable facts in a StructuredArtifact.
Used by the validator to check whether model output references real content.

```python
"""Fact Index for PRISM-HAR validation.

Builds a lookup index from a StructuredArtifact that allows O(1) checks:
- Does this entry_id exist?
- Does this text appear in the raw content of entry N?
- Is this path present in the artifact?
"""

from __future__ import annotations

from dataclasses import dataclass, field
from bola_ai.rag.har_extractor import StructuredArtifact, HarEntry


@dataclass
class FactIndex:
    """Fast lookup index over a StructuredArtifact."""
    entry_by_id: dict[int, HarEntry] = field(default_factory=dict)
    all_hosts: frozenset[str] = frozenset()
    all_paths: frozenset[str] = frozenset()
    all_path_id_segments: frozenset[str] = frozenset()
    entry_raw_texts: dict[int, str] = field(default_factory=dict)   # entry_id → condensed text

    def entry_exists(self, entry_id: int) -> bool:
        return entry_id in self.entry_by_id

    def text_in_entry(self, text: str, entry_id: int) -> bool:
        """Check if text appears verbatim in the raw text of entry entry_id."""
        raw = self.entry_raw_texts.get(entry_id, "")
        return text in raw

    def text_in_any_entry(self, text: str) -> bool:
        return any(text in raw for raw in self.entry_raw_texts.values())

    @classmethod
    def build(cls, artifact: StructuredArtifact) -> "FactIndex":
        """Build index from StructuredArtifact."""
        ...
```

---

### 3. `src/bola_ai/agent/har_analyzer.py`

**Purpose**: Two-pass HAR analysis using the fine-tuned `bola-har` model.
Pass 1 is skipped for HAR (deterministic extractor handles it).
Pass 2 sends the ENTRIES LIST to the `bola-har` Ollama model with grammar constraint.

```python
"""PRISM-HAR two-pass analyzer.

Pass 1: StructuredArtifact already built by HarExtractor (no LLM needed for HAR).
Pass 2: Send ENTRIES LIST to bola-har model with GBNF grammar → Finding JSON.

Returns list[RawFinding] before validation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

from bola_ai.rag.har_extractor import StructuredArtifact
from bola_ai.agent import llm


FINDING_GRAMMAR = r"""
root          ::= "[" ws (finding (ws "," ws finding)*)? ws "]"
finding       ::= "{" ws
                    "\"entry_id\""     ws ":" ws number   ws "," ws
                    "\"pattern_id\""   ws ":" ws string   ws "," ws
                    "\"pattern_name\"" ws ":" ws string   ws "," ws
                    "\"evidence_quote\""  ws ":" ws string ws "," ws
                    "\"attack_delta\""    ws ":" ws string ws "," ws
                    "\"poc_entry_id\""    ws ":" ws number ws "," ws
                    "\"confidence\""      ws ":" ws confidence ws "," ws
                    "\"note\""            ws ":" ws string
                  ws "}"
confidence    ::= "\"high\"" | "\"medium\"" | "\"low\""
number        ::= [0-9]+
string        ::= "\"" ([^"\\] | "\\" .)* "\""
ws            ::= [ \t\n]*
"""

ANALYZER_SYSTEM_PROMPT = """\
You are a BOLA/authorization security analyzer specialized in HTTP Archive (HAR) files.
You MUST analyze ONLY the entries provided in the ENTRIES LIST.
You MUST NOT reference any endpoint, host, ID, or field that does not appear in the entries.
For each finding, evidence_quote MUST be a verbatim substring of the entry you reference.
Output a JSON array of findings only. If no findings: output [].
"""

ANALYZER_USER_TEMPLATE = """\
Analyze the following HAR entries for authorization vulnerabilities (BOLA and related patterns).
Reference only entry IDs from this list. Output JSON array only.

ENTRIES LIST:
{entries_list}
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


class HarAnalyzer:
    """Runs the bola-har specialist model on a StructuredArtifact."""

    HAR_MODEL_NAME = "bola-har"

    def analyze(
        self,
        artifact: StructuredArtifact,
        *,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> list[RawFinding]:
        """
        Send ENTRIES LIST to bola-har model → parse Finding JSON → return RawFinding list.
        Uses GBNF grammar constraint to enforce JSON structure.
        Falls back to empty list on parse error (validator will handle).
        """
        model_name = model or self.HAR_MODEL_NAME
        entries_text = artifact.to_entries_list_text()

        messages = [
            {"role": "system", "content": ANALYZER_SYSTEM_PROMPT},
            {"role": "user", "content": ANALYZER_USER_TEMPLATE.format(entries_list=entries_text)},
        ]

        raw_output = llm.chat(
            messages,
            model=model_name,
            timeout=timeout,
            grammar=FINDING_GRAMMAR,   # grammar kwarg passed to Ollama /api/chat
        )

        return self._parse_findings(raw_output)

    def _parse_findings(self, raw_output: str) -> list[RawFinding]:
        """Parse JSON array from model output. Returns [] on any parse error."""
        ...
```

**Note on `grammar` kwarg**: `llm.chat` must be updated to accept and pass a `grammar` parameter
to Ollama's `/api/chat` endpoint as `"options": {"grammar": grammar_text}`.

---

### 4. `src/bola_ai/agent/validator.py`

**Purpose**: Validate each `RawFinding` against the `FactIndex`. Drop findings with invalid
`entry_id` or `evidence_quote` not found in the entry. Return `ValidatedFinding` list.

```python
"""Finding validator for PRISM-HAR pipeline.

Checks each RawFinding against the FactIndex:
- entry_id must exist in the FactIndex
- evidence_quote must appear verbatim in the raw text of the referenced entry
- poc_entry_id must exist

Returns ValidatedFinding objects with a validation_status field.
Findings that fail are logged as warnings, not silently dropped (for auditability).
"""

from __future__ import annotations

from dataclasses import dataclass
from bola_ai.rag.fact_index import FactIndex
from bola_ai.agent.har_analyzer import RawFinding


@dataclass
class ValidatedFinding:
    entry_id: int
    pattern_id: str
    pattern_name: str
    evidence_quote: str
    attack_delta: str
    poc_entry_id: int
    confidence: str
    note: str
    validation_status: str   # "pass" | "warn_evidence" | "rejected"
    validation_note: str     # "" if pass, reason if warn or rejected


class FindingValidator:
    def __init__(self, index: FactIndex):
        self._index = index

    def validate_all(self, findings: list[RawFinding]) -> list[ValidatedFinding]:
        """
        Validate all findings. Returns only findings with status "pass" or "warn_evidence".
        Rejected findings (invalid entry_id) are dropped and logged.
        """
        ...

    def validate_one(self, finding: RawFinding) -> ValidatedFinding:
        """
        Validate a single finding.

        Rules:
        1. entry_id must exist in FactIndex. If not → status "rejected".
        2. poc_entry_id must exist in FactIndex. If not → demote confidence to "low", add note.
        3. evidence_quote must appear verbatim in entry entry_id raw text.
           If not → status "warn_evidence" (keep finding but flag it, do not drop).
        4. If evidence_quote is empty string → status "warn_evidence".
        """
        ...
```

---

### 5. `src/bola_ai/agent/report_renderer.py`

**Purpose**: Convert validated findings into a markdown report with deterministic curl commands.
The curl is built entirely from `HarEntry` fields — never from LLM text.

```python
"""Deterministic report renderer for PRISM-HAR pipeline.

Takes ValidatedFinding + StructuredArtifact → renders markdown report.
Curls are built from HarEntry fields: method, host, path, query, body params.
The LLM never generates a curl — only the renderer does.
"""

from __future__ import annotations

from bola_ai.agent.validator import ValidatedFinding
from bola_ai.rag.har_extractor import StructuredArtifact, HarEntry

PATTERN_LABELS = {
    "1.1":  "ID in Path Without Ownership Check",
    "1.2":  "Related/Linked Resource Access",
    "1.3":  "Bulk/List Endpoint — No Per-User Filter",
    "1.4":  "Third-Party/Storage API — Guessable Object Key",
    "1.5":  "Multi-Tenant/Cross-Tenant Access",
    "1.6":  "Write Operation Without Ownership Check",
    "1.7":  "Nested Resource Without Parent Authorization",
    "1.8":  "Predictable/Sequential IDs",
    "1.9":  "Batch/Bulk Lookup — No Per-ID Ownership Check",
    "1.10": "Cross-Service Identity Drift",
    "1.11": "Cache-Key Authorization Mismatch",
    "1.12": "Mass Assignment via Object Fields",
    "10.1": "ID Swap in Own Request (Single-Token BOLA)",
    "10.2": "Parameter Escalation — Scope Extension",
    "10.3": "Temporary-ID Hijacking",
    "10.4": "Lifecycle State Bypass",
    "10.5": "Draft/Non-Published Resource Access",
    "10.6": "Subscription/Webhook Hijacking",
}

CONFIDENCE_ICON = {"high": "🔴", "medium": "🟡", "low": "⚪"}


class ReportRenderer:

    def render(
        self,
        findings: list[ValidatedFinding],
        artifact: StructuredArtifact,
        *,
        include_evidence_chain: bool = True,
    ) -> str:
        """Render full markdown report from validated findings + artifact."""
        if not findings:
            return self._render_no_findings(artifact)
        sections = [self._render_header(artifact, len(findings))]
        for finding in findings:
            entry = artifact.entries[finding.entry_id - 1]
            sections.append(self._render_finding(finding, entry, artifact))
        return "\n\n---\n\n".join(sections)

    def _render_finding(
        self,
        finding: ValidatedFinding,
        entry: HarEntry,
        artifact: StructuredArtifact,
    ) -> str:
        """Render one finding section including deterministic PoC curl."""
        curl = self._build_curl(entry, finding, artifact)
        ...

    def _build_curl(
        self,
        entry: HarEntry,
        finding: ValidatedFinding,
        artifact: StructuredArtifact,
    ) -> str:
        """
        Build syntactically valid curl from HarEntry fields.

        The curl:
        - Uses entry.method, entry.host, entry.path, entry.query_string
        - Injects auth header from artifact.auth_context
        - For POST: reconstructs body from entry.body_params or entry.body_json
          + applies finding.attack_delta to modify exactly the field under test
        - Never uses any text from the LLM output

        Returns: multi-line curl string ready to paste into terminal.
        """
        ...

    def _render_no_findings(self, artifact: StructuredArtifact) -> str:
        """Render a clean 'no findings' report with summary of what was analyzed."""
        ...
```

---

### 6. `src/bola_ai/rag/rag_isolation.py`

**Purpose**: Enforce session-scoped RAG. Move contaminating fixture documents out of the
shared RAG collection. This is the P1 ANCHOR fix.

```python
"""RAG isolation for PRISM-HAR pipeline.

Problem: fixture/benchmark docs in shared_docs/ contaminate every analysis by being
auto-ingested into the shared ChromaDB collection at container start.

Solution: a whitelist of allowed knowledge sources + a session-scoped source filter
that restricts RAG retrieval to only the user's uploaded docs + canonical knowledge.

This module is used by runner.py to build the source_filter for every analysis call.
"""

from __future__ import annotations

from pathlib import Path

# Canonical knowledge sources — always allowed in RAG
KNOWLEDGE_SOURCES = frozenset([
    "bola_patterns.md",
    "ai_teacher_bola_quality_patterns.md",
    "phase1_small_model_guidelines.md",
])

# Fixture/adversarial documents that must NOT be in the shared RAG collection
# These should be moved to tests/fixtures/ and never ingested at runtime
CONTAMINATING_DOCS = frozenset([
    "doc_benchmark_salesforce_har_like_20260330.md",
    "doc_adversarial_salesforce.md",
    "doc_adversarial_graphql.md",
    "context.txt",
    "doc_crm_contacts.md",
])


def build_session_source_filter(user_doc_sources: list[str]) -> list[str]:
    """
    Build a source filter that includes only:
    1. Canonical knowledge sources
    2. User-uploaded docs for this session

    Excludes any source in CONTAMINATING_DOCS.
    """
    allowed = list(KNOWLEDGE_SOURCES)
    for src in user_doc_sources:
        basename = Path(src).name
        if basename not in CONTAMINATING_DOCS:
            allowed.append(src)
    return allowed


def get_contaminating_docs_in_store(store) -> list[str]:
    """
    Scan the ChromaDB collection and return any source names that match CONTAMINATING_DOCS.
    Used at startup to warn about contamination.
    """
    ...
```

---

## Existing Files to Modify

### 7. `src/bola_ai/agent/llm.py` — Add `grammar` parameter

Add `grammar: Optional[str] = None` to `chat()`. If provided, pass it to Ollama as:
```python
options = {}
if grammar:
    options["grammar"] = grammar
# include options in the request body if non-empty
```

The Ollama API accepts `grammar` in the `options` dict for GBNF-constrained generation.

### 8. `src/bola_ai/agent/runner.py` — HAR detection + routing

Add HAR detection at the beginning of `run_analysis` / `analyze_for_bola`:

```python
# At the top of run_analysis, before RAG retrieval:
from bola_ai.rag.har_extractor import HarExtractor
from bola_ai.agent.har_analyzer import HarAnalyzer
from bola_ai.agent.validator import FindingValidator
from bola_ai.agent.report_renderer import ReportRenderer
from bola_ai.rag.fact_index import FactIndex

extractor = HarExtractor()
# Check if the query or the RAG context contains a HAR artifact
if extractor.is_har(query) or _context_contains_har(store, source_filter):
    try:
        return _run_har_pipeline(store, query, source_filter=source_filter, ...)
    except Exception as e:
        logger.warning(f"HAR pipeline failed, falling back to general: {e}")
        # fall through to existing flow
```

`_run_har_pipeline` orchestrates HarExtractor → FactIndex → HarAnalyzer → FindingValidator →
ReportRenderer. It is a new private function in runner.py.

`_context_contains_har` checks if any user doc in the source_filter is a HAR file (by checking
ChromaDB metadata or by reading a sample chunk for HAR JSON structure).

### 9. `src/bola_ai/api/app.py` — HAR detection at ingest time

At `/ingest` and `/ingest_shared`, detect if the content is HAR JSON:
- If yes: store `metadata={"source": filename, "artifact_type": "har"}` in ChromaDB
- This metadata allows `_context_contains_har` in runner.py to quickly find HAR sources

No other changes to `app.py` — the routing happens in runner.py.

### 10. `docker/Modelfile` → Add `bola-har` model

Create a second Modelfile `docker/Modelfile.bola-har`:

```
FROM qwen2.5-coder:3b

PARAMETER temperature 0.3
PARAMETER top_p 0.85
PARAMETER repeat_penalty 1.2

SYSTEM """
You are a BOLA/authorization security analyzer for HTTP Archive (HAR) files.
You receive a structured ENTRIES LIST from a real HAR capture.
You output a JSON array of findings. Each finding references an entry_id from the list.
Every evidence_quote must be a verbatim substring of the referenced entry.
If no authorization vulnerabilities are found, output [].
"""
```

### 11. `docker/Dockerfile.allinone` — Bake `bola-har` model

Add after the existing `ollama create bola-analyzer` step:
```dockerfile
# Bake HAR specialist model (adapter merged at build time)
COPY models/merged/bola-har-merged/ /app/models/merged/bola-har-merged/
COPY docker/Modelfile.bola-har /app/Modelfile.bola-har
RUN ollama serve & sleep 8 && \
    ollama create bola-har -f /app/Modelfile.bola-har && \
    pkill ollama
```

Note: this requires the merged adapter to exist at build time. The merge step runs as part of
the post-training pipeline (`scripts/post_training_package_and_push.py`).

### 12. `configs/training/qlora_har_specialist.yaml` — New training config

```yaml
run_name: qlora_har_specialist
mode: qlora
base_model: Qwen/Qwen2.5-Coder-3B-Instruct
dataset:
  sft_train: data/training/sft/bola_har_specialist_train.jsonl
  sft_valid: data/training/sft/bola_har_specialist_eval.jsonl
quantization:
  load_in_4bit: true
  quant_type: nf4
  compute_dtype: bfloat16
precision:
  dtype: bfloat16
lora:
  r: 32
  alpha: 64
  dropout: 0.05
  target_modules:
    - q_proj
    - k_proj
    - v_proj
    - o_proj
    - gate_proj
    - up_proj
    - down_proj
training:
  per_device_train_batch_size: 8
  gradient_accumulation_steps: 2
  learning_rate: 0.0002
  num_train_epochs: 3
  max_steps: 0
  gradient_checkpointing: true
  optimizer: paged_adamw_8bit
  max_seq_length: 2048
  sample_packing: false
  warmup_steps: 50
  lr_scheduler_type: cosine
  weight_decay: 0.01
  save_strategy: steps
  save_steps: 50
  save_total_limit: 3
  evaluation_strategy: steps
  eval_steps: 100
  load_best_model_at_end: true
  metric_for_best_model: eval_loss
  logging_steps: 10
outputs:
  adapters_dir: models/adapters
  merged_dir: models/merged
```

---

## Execution Order (Non-Negotiable)

1. Create new files in this order (dependencies):
   - `har_extractor.py` (no deps on new code)
   - `fact_index.py` (depends on har_extractor)
   - `har_analyzer.py` (depends on llm, har_extractor)
   - `validator.py` (depends on fact_index, har_analyzer)
   - `report_renderer.py` (depends on validator, har_extractor)
   - `rag_isolation.py` (no deps on new code)

2. Modify existing files:
   - `llm.py` (add grammar param — tiny change)
   - `app.py` (HAR metadata at ingest)
   - `runner.py` (HAR routing — most complex change)

3. Create config:
   - `qlora_har_specialist.yaml`

4. Create Docker artifacts:
   - `Modelfile.bola-har`
   - Update `Dockerfile.allinone`

---

## Test Requirements

Each new module needs a test file:
- `tests/test_har_extractor.py` — test extraction from real HAR fixture
- `tests/test_fact_index.py` — test index lookups
- `tests/test_har_analyzer.py` — test with mock LLM output (no real Ollama needed)
- `tests/test_validator.py` — test pass/warn/reject logic with controlled inputs
- `tests/test_report_renderer.py` — test curl generation for each pattern type
- `tests/test_rag_isolation.py` — test source filter construction

Existing tests must all continue to pass after modifications.

---

## Definition of Refactoring Complete

- [ ] All 6 new modules created with full implementation (no `...` stubs)
- [ ] `llm.py` grammar parameter added
- [ ] `runner.py` HAR routing wired up and tested
- [ ] `app.py` HAR metadata at ingest
- [ ] `qlora_har_specialist.yaml` created
- [ ] `Modelfile.bola-har` created
- [ ] All existing tests pass (`pytest tests/` green)
- [ ] New tests for each new module pass
- [ ] Manual smoke test: `POST /ingest` with HAR JSON → `POST /analyze` → non-empty report
