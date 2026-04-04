# Small-Model Teaching Phase 1 Plan

## Objective

Raise security vulnerability analysis quality on a local model baseline without requiring larger-model fallback.

## Scope of Phase 1

- Enforce a compact, grounded response contract across the vulnerability taxonomy.
- Generate diverse cross-domain training tasks (API docs, schemas, network logs).
- Gate all generated examples before accepting them into training/RAG.
- Validate quality with standard agent prompt flow (tests + adaptive E2E).

## Implemented in this phase

1. **Local model baseline policy**
   - Runtime/build defaults use a local model via Modelfile and compose/entrypoint paths.

2. **Phase-aware AI teaching tasks**
   - `scripts/generate_ai_training_tasks.py` now supports `--phase small-model-phase1` (default).
   - Phase 1 uses curated medium-complexity tasks and stricter compact output prompts.

3. **Smaller-model response contract**
   - Added `PHASE1_SMALL_MODEL_INSTRUCTIONS` and `PHASE1_EXPECTED_RESPONSE_PROMPT` in `src/training/ai_teacher_prompts.py`.
   - Forces concise findings, class-appropriate verification logic (comparative checks where needed), grounding self-check, and explicit uncertainty statement.

4. **Recurring teaching-cycle gate runner**
   - Added `scripts/run_ai_teaching_cycle.py` for recurring teacher/reviewer acceptance cycles.
   - Produces accepted/rejected packs and per-cycle summary with acceptance-rate delta (`data/training/ai_cycles/`).

## How to run Phase 1 data generation

```bash
PYTHONPATH=src python scripts/generate_ai_training_tasks.py --phase small-model-phase1
```

The script writes JSONL task packs into `data/training/ai_tasks/`.

Run a gate cycle on the generated pack:

```bash
PYTHONPATH=src python scripts/run_ai_teaching_cycle.py \
  --task-pack data/training/ai_tasks/<teacher_tasks_*.jsonl> \
  --output-dir data/training/ai_cycles
```

Cycle output includes:
- `accepted_*.jsonl` (gate-passing examples)
- `rejected_*.jsonl` (examples that need improvement)
- `teaching_cycle_summary_*.json` (acceptance metrics + delta)

## Phase 1 acceptance gates

- Grounding: every endpoint/object in answers exists in source artifact.
- Vulnerability specificity: findings are evidence-grounded security issues from the taxonomy.
- Verification validity: comparative checks for object-boundary claims; class-appropriate checks for other findings.
- Compactness: concise, evidence-first findings; no generic filler and no forced finding count.
- Uncertainty discipline: explicit unknowns when docs are incomplete.

## Exit criteria

- Standard automated tests pass.
- Standard adaptive E2E loop completes with actionable, grounded outputs.
- No placeholder path leaks or malformed endpoint blocks in the final report.
