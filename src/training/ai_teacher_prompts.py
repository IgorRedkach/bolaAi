"""Prompt pack for manual high-fidelity learning-set authoring."""

from __future__ import annotations

from dataclasses import dataclass

TAXONOMY_PATH = "/home/iredkach/Downloads/bola/bolaAi/data/knowledge/bola_patterns.md"

TEACHER_SYSTEM_PROMPT = """You are a Principal Security Architect and Incident Investigation Lead.
You create enterprise-grade training artifacts from scratch for each learning set.
Do not reuse prior set templates, copy/paste filler blocks, repetitive expansion rows, or synthetic padding text.
Every artifact must read like authentic engineering documentation with concrete domain logic and cross-document consistency.
"""

LEARNING_PATH_INTENT = """For EVERY learning set follow this strict path:
1) Select a plausible industry.
2) Analyze that industry and create a realistic architecture.
3) Plan documentation strategy (what docs are required and why).
4) Create architecture and technical documentation with total documentation size >= 10MB.
5) Map and embed plausible vulnerabilities from taxonomy ({taxonomy_path}) into that architecture documentation.
6) Decide whether logs/HAR are needed for this set (optional and scenario-driven).
7) Build context from documentation first; add logs/HAR only if justified.
8) Analyze evidence and produce expected_response with reproducible verification steps.
9) Produce a separate analysis_explanation file describing reasoning and evidence selection.
"""

DOC_STRATEGY_PROMPT = """Given selected industry and architecture intent, propose documentation strategy.
Return JSON:
- documentation_objective
- required_doc_families (array)
- optional_doc_families (array)
- excluded_doc_families (array)
- rationale_per_family (object)
- target_doc_bytes_total (integer; must be >= 10485760)
- anti_repetition_controls (array)

Rules:
- strategy must vary from prior sets
- prefer deeply connected documents over many shallow summaries
- no filler-style content plans
"""

INDUSTRY_ARCHITECTURE_PROMPT = """{learning_path_intent}

Task: choose one industry and propose one realistic enterprise system.
Output format: JSON object only with keys:
- industry
- business_context
- system_name
- architecture_overview
- trust_boundaries (array)
- services (array of objects: name, purpose, trust_boundary, interfaces)
- data_stores (array of objects: name, type, data_classes)
- identity_and_authz_model
- operational_workflows (array)
- likely_failure_modes (array)

Guidance:
- design from scratch for this set; avoid prior set structure reuse
- include meaningful domain-specific logic, not generic microservice descriptions
- include synchronous and/or asynchronous flows when scenario requires
- include operational and compliance constraints relevant to this industry
"""

PATTERN_SELECTION_PROMPT = """Given architecture and taxonomy, select 3-6 vulnerability classes that are
credible for this system. Prefer authorization and boundary failures when supported.
Taxonomy path: {taxonomy_path}

Return JSON object:
- selected_patterns (array)
- architecture_alignment (object pattern->why it fits this architecture)
- embedding_locations (object pattern->candidate artifacts/files where signal appears)

Architecture summary:
{architecture_summary}
"""

DOCUMENT_BLUEPRINT_PROMPT = """Build a documentation blueprint for one learning set.
Return JSON object with key `documents` (array). For each document provide:
- filename
- doc_type
- purpose
- required_sections (array)
- embedded_vulnerability_signals (array)
- cross_references (array of related files)
- target_size_bytes (integer)
- realism_constraints (array)

Artifact menu (choose what fits the scenario and available evidence):
- architecture design notes
- API contract/specification
- DB schema or query snippets
- role/access/permission notes
- operational runbook or troubleshooting notes
- runtime logs/telemetry extracts
- change-management, incident, or ticket documentation
- interface control documents
- compliance control narratives
- failure mode analyses

Important:
- a learning set may contain a single document or many documents
- prioritize realism and evidence quality over fixed artifact count
- vary document families across sets; do not repeat the same bundle structure
- total of document target sizes must be >= 10MB before any optional logs/HAR
- avoid repetitive row-pattern inflation as a sizing mechanism
"""

DOCUMENT_SCALE_AND_VARIABILITY_PROMPT = """Before writing documents, plan scale and variability.
Return JSON:
- target_doc_bytes_total (integer)
- doc_only_mode (boolean)
- selected_document_families (array)
- excluded_families (array)
- rationale

Rules:
- in doc_only_mode, documentation itself must exceed 10MB total without logs/HAR
- prefer large deep-spec documents over small summaries
- avoid repeating same document composition across consecutive sets
- no repetitive filler or synthetic padding patterns
"""

DOCUMENT_CONTENT_PROMPT = """Generate final content for ONE document from blueprint item.
Inputs:
- architecture summary
- selected patterns
- blueprint item

Rules:
- output plain text only (no fences)
- include concrete IDs, routes, identities, tables, and workflow details
- include realistic process detail and operational constraints
- embed vulnerability signals subtly (not explicit labels)
- keep content grounded and internally consistent with previously generated artifacts
- do not use repetitive synthetic expansion rows to increase size
- size must come from genuine specification depth and cross-referenced detail
"""

VULNERABILITY_EMBEDDING_PROMPT = """Given completed documentation and taxonomy, embed vulnerabilities realistically.
Return JSON:
- embedded_vulnerabilities (array)
- per_vulnerability_evidence_locations (object)
- why_plausible_in_architecture (object)
- false_positive_risks (array)

Rules:
- use taxonomy at {taxonomy_path}
- vulnerabilities must arise from architecture/process design, not random insertion
- each embedded vulnerability must be traceable to specific document sections
"""

LOG_DECISION_PROMPT = """Decide whether logs/HAR should be added for this set.
Return JSON:
- add_logs_or_har (boolean)
- decision_rationale
- if_added_artifacts (array)

Rules:
- documentation already satisfies >=10MB
- logs/HAR are optional and scenario-driven
- do not add logs/HAR just for size
"""

EXPECTED_RESPONSE_PROMPT = """Analyze the context pack and produce `expected_response.md`.
Required structure:
1) Findings (prioritized)
2) Evidence map (file-level references)
3) Reproduction steps per finding
4) Expected vulnerable vs expected secure behavior
5) Remediation actions
6) Residual risk and validation checklist

Hard rule: no finding without direct evidence.
"""

EXPLANATION_PROMPT = """Generate `analysis_explanation.md` as separate reasoning trace.
Include:
- how context was parsed and prioritized
- decision criteria for keeping vs rejecting candidate findings
- evidence-to-finding mapping method
- uncertainty and confidence notes
- why each kept finding is grounded
Do not add new findings beyond expected_response evidence.
"""

REVIEW_PROMPT = """Review `expected_response.md` and `analysis_explanation.md` against context.
Return JSON:
- grounded (true/false)
- issues (array)
- missing_evidence (array)
- overclaims (array)
- fixed_expected_response
- fixed_explanation
"""

AUTHENTICITY_REVIEW_PROMPT = """Review generated documentation for authenticity.
Return JSON:
- authentic_style (true/false)
- copy_paste_or_padding_patterns (array)
- repeated_block_signatures (array)
- realism_gaps (array)
- required_rewrites (array)
Reject documents that look templated, repetitive, or mechanically inflated.
"""

CHECKPOINT_TRACKING_PROMPT = """Create a checklist report for this learning-set run.
Output markdown with checkboxes for:
- Industry selected and justified
- Architecture created and detailed
- Documentation strategy planned
- Documentation bundle generated
- Vulnerability classes selected from taxonomy and embedded
- Optional log/HAR decision recorded
- Context assembled
- Expected response generated with reproducible steps
- Explanation generated separately
- Grounding review completed
- Authenticity review completed
Include file paths and size notes where possible.
Include explicit `doc_bytes_total_excluding_logs_har`.
"""


@dataclass(frozen=True)
class TrainingTask:
    sector: str
    architecture: str
    artifact_types: str
    complexity: str
    required_patterns: str


@dataclass(frozen=True)
class ArtifactBlueprint:
    name: str
    structural_constraints: str
    noise_fields: str


def build_scenario_prompt(task: TrainingTask) -> str:
    return (
        f"{LEARNING_PATH_INTENT.format(taxonomy_path=TAXONOMY_PATH)}\n"
        f"Industry: {task.sector}\n"
        f"Architecture hint: {task.architecture}\n"
        f"Artifact types: {task.artifact_types}\n"
        f"Complexity: {task.complexity}\n"
        f"Required patterns: {task.required_patterns}\n"
    )
