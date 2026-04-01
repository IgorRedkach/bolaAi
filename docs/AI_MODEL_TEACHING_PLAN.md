# AI-Assisted Teaching Plan (7B-first, national-grade)

## Goal

Create a reproducible, offline-capable training workflow that uses AI agents to generate, critique, and refine high-quality BOLA training artifacts and gold responses across domains (government, healthcare, finance, utilities).

This plan targets:
- stronger grounding
- better BOLA reasoning depth
- stricter verification logic
- higher auditor usefulness

## Why this is needed

- Runtime quality still depends on model reasoning + prompt consistency.
- Complex HAR/Salesforce/GraphQL scenarios need deeper examples than static seed data.
- We need domain-general standards, not examples tied to one product only.

## Parallelizable workstreams

When waiting on model inference, image build, or long test runs, run these in parallel:

1. **Scenario generation stream**
   - Generate synthetic artifacts: API docs, schemas, and network logs.
   - Enforce realistic role/tenant/ownership rules.

2. **Gold response stream**
   - For each artifact, produce expected BOLA findings and two-token verification runbooks.
   - Include anti-pattern guardrails (what is not BOLA).

3. **Review stream**
   - Critique generated outputs using a fixed scoring rubric.
   - Reject low-grounding or auth-only reasoning.

4. **Autotest stream**
   - Convert failures into deterministic regression tests for normalization/prompt rules.

## AI prompt stack

Prompt templates live in `src/training/ai_teacher_prompts.py`.

- `TEACHER_SYSTEM_PROMPT`: security-engineer behavior contract.
- `SCENARIO_AUTHOR_PROMPT`: generate realistic artifacts with injected risks.
- `EXPECTED_RESPONSE_PROMPT`: produce grounded gold outputs.
- `REVIEW_PROMPT`: score/correct generated outputs.

## Task-pack generation

Use:

`PYTHONPATH=src python scripts/generate_ai_training_tasks.py`

This writes JSONL task packs to:

`data/training/ai_tasks/teacher_tasks_<timestamp>.jsonl`

Each task contains:
- scenario prompt
- expected-response prompt
- review prompt
- metadata (sector, architecture, artifact type, complexity)

## Quality gates before data is accepted

Every generated example must pass:

1. **Grounding gate**: all paths/objects in expected response must appear in source artifact.
2. **BOLA gate**: findings must be object-level authz, not generic auth failures.
3. **Verification gate**: two valid user tokens/users on same object ID.
4. **Format gate**: deterministic section layout for training stability.
5. **Actionability gate**: auditor can execute steps without ambiguity.

Reject and regenerate on any gate failure.

## Training loop

1. Generate task pack.
2. Use local AI agents to produce artifact + expected response + review.
3. Keep only PASS examples.
4. Append accepted examples to:
   - `data/training/bola_training.jsonl`
   - `data/training/bola_rag_chunks.txt` (derived snippets for retrieval)
5. Reload RAG:
   - `PYTHONPATH=src python src/training/load_knowledge.py`
6. Rebuild/refresh model package if prompt/model assets changed.
7. Run full automated + adaptive E2E validation.
8. If failures appear, create issue + regression test, then iterate.

## Model policy

- Keep `7b` as quality default for production-grade security analysis.
- Use this teaching loop to continuously improve both:
  - 7b behavior (prompt + curated data)
  - future small-model candidates (distillation/fine-tuning track)

## National-interest reliability policy

- No internet required at runtime.
- No user-data exfiltration.
- Highest priority: grounded, reproducible, auditor-actionable vulnerability guidance.
- Any quality regression is treated as a tracked issue with a test before closure.

