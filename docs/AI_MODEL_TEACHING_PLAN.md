This refactored **AI-Assisted Teaching Plan** eliminates "BOLA-only" bias by establishing a universal reasoning framework. It ensures that the "Oracle" (the high-order orchestrator) and the "Worker" (the 3B model) are trained on the **logic of failure** across all seven security classes, rather than just keyword patterns.

---

# AI-Assisted Teaching Plan (Small-Model-First, National-Grade)

## Goal

Create a reproducible, offline-capable training workflow that uses AI agents to generate, critique, and refine high-fidelity security vulnerability artifacts and gold-standard responses. This pipeline targets "National-Grade" reliability across critical sectors (Government, Defense, Healthcare, FinTech, and Industrial Control).

The objective is to eliminate model bias and ensure:
- **Total Taxonomy Grounding**: Mastery of BOLA, BAC, Insecure Design, Integrity Failures, Injection, Misconfiguration, and Logging Gaps.
- **Semantic Reasoning Depth**: Identifying the *absence* of logical invariants rather than matching keywords.
- **Deterministic Verification**: Forcing every "Gold Response" to include a falsifiable Proof of Concept (PoC) with real data context.
- **Zero-Internet Autonomy**: Maintaining a high-quality local intelligence baseline (3B-class) that outperforms larger cloud models via superior "Teaching Data."

## Why this is needed

- **Logic vs. Pattern Matching**: Small models tend to default to generic "Authentication" advice. We need data that teaches the difference between "Valid Login" and "Unauthorized Logic."
- **Evidence-to-Hypothesis Mapping**: Training the model to cite specific lines in a log or schema as the "Root Cause" of a logic gap.
- **Cross-Domain Standard**: Ensuring that a "Race Condition" or "Confused Deputy" is recognized regardless of whether the system is GraphQL, Salesforce, or a custom ERP sync.

## Advanced Framework Alignment (3B-first)

This training plan is aligned to an "Action -> Assertion + Invariant" auditing paradigm:
- **Action -> Assertion**: each generated task encodes a concrete action and a falsifiable secure/vulnerable assertion.
- **Invariant-first checks**: object ownership invariants and role invariants are evaluated before narrative generation.
- **Reasoning matrix**: outputs must preserve scope control, evidence grounding, reasoning constraints, and security classification.
- **Contrastive learning signal**: rejected answers are failure-specific (placeholder paths, protocol hallucination, auth-only checks), not generic low-quality text.
- **Correctness over latency**: slower model responses are acceptable when they improve groundedness and authorization logic accuracy.

## Parallelizable Workstreams

1. **Scenario Generation Stream (The "Adversary")**
   - Produces high-fidelity synthetic artifacts (OpenAPI, HAR Traces, Database Schemas, gRPC Protos).
   - Injects "Silent" failures where security controls are missing, bypassable via context, or trust the client.

2. **Gold Response Stream (The "Oracle")**
   - Analyzes artifacts to produce a multi-vector report.
   - Mandates the **Two-Token Invariant** for horizontal boundaries and **Method/Role Mismatch** for vertical boundaries.
   - Extracts real tokens/URLs from context into runnable PoC `curl` commands.

3. **Gated Review Stream (The "Auditor")**
   - Critiques artifacts and responses via a 0-5 scoring rubric.
   - Enforces a "Strict Logic" policy: Reject any finding that confirms a logic gap using `401 Unauthorized` or `404 Not Found`.

4. **Autotest Stream (The "Regulator")**
   - Converts rejected artifacts or model "slips" into deterministic regression tests in `tests/test_e2e_loop_failures.py`.

## AI Prompt Stack

Prompt templates are maintained in `src/training/ai_teacher_prompts.py` as formal contracts:
- `TEACHER_SYSTEM_PROMPT`: Defines the Principal Security Architect persona and taxonomy.
- `SCENARIO_AUTHOR_PROMPT`: Directs the creation of artifacts with deterministic logic gaps.
- `EXPECTED_RESPONSE_PROMPT`: Enforces the Oracle reporting format (Observation -> Hypothesis -> PoC).
- `REVIEW_PROMPT`: The final gatekeeper scoring grounding and logical proof validity.

## High-Fidelity Synthetic Artifact Engine

The pipeline now separates generation into two layers:
1. **Structural logic seed prompt** (`SCENARIO_AUTHOR_PROMPT`) that forces explicit positive/negative authorization logic pairs.
2. **Deterministic artifact templates** in `scripts/generate_ai_training_tasks.py` (OpenAPI, HAR-like JSON, SQL DDL) that wrap logic into enterprise-shaped telemetry.

This improves data quality for 3B-class models by reducing format drift and preserving structural invariants.

## Task-Pack Generation

Command:
`PYTHONPATH=src python scripts/generate_ai_training_tasks.py`

Output:
`data/training/ai_tasks/teacher_tasks_<timestamp>.jsonl`

## Quality Gates (The "No-Shortcut" Policy)

Every generated training pair must pass:

1. **Grounded Entity Gate**: Every URI, header, and field in the response must be verbatim from the source artifact.
2. **Logical Proof Gate**: Findings must identify an *Authorization* or *Logic* failure, not a lack of *Authentication*.
3. **Verification Integrity Gate**: Procedures must be falsifiable (Define "Secure Outcome" vs. "Vulnerable Outcome").
4. **Data Integrity Gate**: PoC commands MUST use real URLs and Tokens if they exist in the artifact/logs.
5. **Uncertainty Discipline Gate**: Explicitly marks undocumented ownership as `## [UNCERTAINTY]` instead of guessing.

## Training Loop (Continuous Improvement)

1. **Task Generation**: Build a task pack with diverse Sector/Architecture combinations.
2. **Local Execution**: Use the stack to generate Artifact + Gold Response + Review.
3. **Acceptance**: Only PASS examples (Score >= 4 across all categories) are kept.
4. **Persistence**:
   - Append to `data/training/bola_training.jsonl` (for fine-tuning).
   - Update `data/training/bola_rag_chunks.txt` (for real-time retrieval).
5. **Deployment**: Reload RAG store and rebuild the local Ollama model.
6. **Validation**: Run the adaptive E2E loop with *new* adversarial data to ensure no logic regression.

## Model Policy

- **Baseline Accountability**: Standardized on **3B/3.5B local models** (e.g., Qwen 2.5 Coder 3B). 
- **Quality via Data**: We reject the "Large Parameter" bias. We achieve world-class results by providing the small model with cleaner logic and stricter boundaries.
- **Distillation Target**: The teaching loop generates the data used to distill higher-level security reasoning into the production-ready small weights.

## National-Interest Reliability Policy

- **Total Isolation**: Zero internet requests from the tool at runtime.
- **Exfiltration Proof**: No user-ingested data leaves the ephemeral container.
- **Audit Traceability**: Every finding must be reproducible by a human analyst using the provided PoC.
- **Fail-Fast Testing**: Any reasoning drift (e.g., a "Regression") is logged in `docs/ISSUES.md` and blocks release.