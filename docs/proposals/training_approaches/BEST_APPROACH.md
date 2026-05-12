# Best Approach — Current Decision

**Status:** In Progress — GPU unavailable, prompt-only approaches implemented  
**Date:** 2026-05-12

## Blocker

No GPU / no `unsloth` available in this environment. QLoRA fine-tuning (Approaches B, C, D) cannot be executed locally. All training examples have been generated and merged into `data/training/sft/train.jsonl` for execution when a GPU environment is available.

## Current Best Approach: A + E Combined (Prompt Engineering + Evidence-First Gate)

### What was implemented:

**`src/bola_ai/agent/prompts.py`:**
- Added `MANDATORY CLASSIFICATION GATE` with 5 explicit gates in priority order.
- Gate 1/2/3 explicitly state "ONE session" and "Do NOT add a second user."
- Gate 4 explicitly states "ONLY if Gates 1-3 are all NO" and requires justification.
- Added `EVIDENCE MAP` requirement: evidence table must appear before any finding claim.
- Updated user prompt template to lead with the gate check and evidence table requirement.
- Updated grounding suffix to reference gate numbers.
- Updated output format to include Gate number in finding header.

**`docker/Modelfile`:**
- Lowered temperature from 0.7 → 0.35 (reduces stochastic drift toward memorized templates).
- Lowered top_k from 40 → 30 (tighter sampling).
- Increased repeat_penalty from 1.1 → 1.15.
- Rewrote system prompt to match gate-based approach.
- Added two new few-shot examples: one Gate 1 (field injection, REST), one Gate 2 (write escalation).

### Why this should fix the bias:

| Old behavior | New behavior |
|--------------|--------------|
| Tunnel vision to "Actor A vs Actor B" | Must pass Gate 1/2/3 check before reaching Gate 4 |
| Evidence after claim | Evidence table BEFORE claim — forces artifact-grounded reasoning |
| One template for all findings | Gate number in output — auditable per finding |
| Temperature 0.7 — high drift | Temperature 0.35 — more deterministic |
| No write escalation few-shot | Gate 2 write escalation example in Modelfile |

### Training data improvements:

14 new diverse examples added to `data/training/sft/train.jsonl`:
- 7 × Gate 1 field injection (healthcare, fintech, government, HR, energy grid, telecom, legal)
- 7 × Gate 2 write escalation (insurance, edtech, real estate, pharma, supply chain, proptech, medtech)
- All examples: different domains, no "RISK-xxx" labels, realistic but non-hinting documents
- 2 holdout examples for testing (example_08 from each type)
- 1 combined test example (both Gate 1 + Gate 2 in same document, IoT platform)

### Next steps when GPU is available:

1. Run `scripts/train_qlora_unsloth.py` with `data/training/sft/train.jsonl` (717 examples total).
2. Run contrastive DPO pass: generate rejected responses for the 14 new examples (add to bola_har_specialist_dpo.jsonl).
3. Test against holdout examples (examples_08 from both types, combined test).
4. Iterate prompt if any gate misclassification observed.

## Rubric Projections (pending live test)

| Parameter | Expected improvement |
|-----------|---------------------|
| Priority order followed | HIGH — explicit gate ordering |
| Evidence grounding | HIGH — mandatory evidence table |
| Single-user-first | HIGH — gate 1/2/3 explicitly state "one session" |
| Hallucinated endpoints | MEDIUM — no change to grounding rules |
| Curl correctness | MEDIUM — few-shot examples show correct patterns |
| Vulnerability class breadth | HIGH — 14 new diverse examples cover 8 classes |
| No bias / no tunnel vision | HIGH — gate structure breaks Actor A/B default path |
| Actionability | MEDIUM — dependent on model following format |
