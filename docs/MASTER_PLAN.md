# Master Execution Plan

> **Single source of truth.** All other planning docs are superseded by this file.
> Checked boxes = done and merged to main. Unchecked = pending or in-progress.

---

## Phase 1 — Model Lock-in: Qwen2.5-Coder-3B-Instruct Only

- [x] **1.1** Remove `--auto-fallback-models` parameter logic from `run_three_cycle_retrain_loop.py` (no smaller fallback models allowed)
- [x] **1.2** Hard-code `TRAINING_MODEL = "Qwen/Qwen2.5-Coder-3B-Instruct"` constant; removed `--base-model` and `--auto-fallback-models` CLI args
- [x] **1.3** `docker/Modelfile` `FROM qwen2.5-coder:3b` verified correct
- [x] **1.4** Default `--retrain-timeout-sec` set to `14400` (4 h for 3B); max-steps default 200
- [x] **1.5** All `tiny-gpt2`, `1.5B`, `0.5B` references removed from scripts

---

## Phase 2 — Manual Testing Methodology Rewrite

- [ ] **2.1** Find every occurrence of the old manual-testing explanation ("use two different user tokens / User A / User B" test recipe) in:
  - `src/bola_ai/agent/prompts.py`
  - `docker/Modelfile` (few-shot examples)
  - `data/knowledge/bola_patterns.md`
  - `src/training/ai_teacher_prompts.py`
  - `scripts/run_manual_test_cases.py`
  - `scripts/run_agent_e2e_loop_once.py`
- [ ] **2.2** Replace with new methodology: *"For each tool request you receive, first analyse the artifact yourself with your full model capacity and produce your own best response independently. Then compare that self-generated response with the tool's actual response, record discrepancies and quality differences in a structured comparison log, and use those findings to drive prompt and training improvements."*
- [ ] **2.3** Delete all "User A / User B" two-person narrative framing from:
  - `src/bola_ai/agent/prompts.py` — remove "User A swapping IDs" phrasing
  - `docker/Modelfile` few-shot examples — rewrite to attacker/single-user perspective where correct
  - `data/knowledge/bola_patterns.md` test descriptions — replace two-user steps with single-user escalation steps where one user is extending their own permissions
  - `src/training/ai_teacher_prompts.py` — strip User A/B language from prompts
- [ ] **2.4** In `bola_patterns.md` section 1.1 and all "Test:" lines: rephrase to acknowledge that many BOLA cases involve a **single authenticated user** who changes an ID in their own request to reach an object they do not own — two distinct user accounts are only needed for ownership-boundary tests

---

## Phase 3 — Data Generation Prompts Awareness of bola_patterns.md

- [ ] **3.1** Audit `src/training/generate_data.py`: confirm every generation function imports or references the full `bola_patterns.md` pattern taxonomy (sections 1–9)
- [ ] **3.2** Add a `_PATTERN_TAXONOMY` constant in `generate_data.py` that is the parsed contents of `bola_patterns.md` (or a structured subset), injected into every generation prompt
- [ ] **3.3** Audit `src/training/ai_teacher_prompts.py`: inject the pattern taxonomy reference into `EXPECTED_RESPONSE_PROMPT` and `REVIEW_PROMPT`
- [ ] **3.4** Verify every adversarial example generator in `generate_data.py` has explicit coverage for at minimum one finding from each of the 9 pattern sections

---

## Phase 4 — Extend bola_patterns.md Classification

- [ ] **4.1** Review all hardcoded scenario templates in `generate_data.py` (lines 40–900+) and map each to a specific `bola_patterns.md` section
- [ ] **4.2** Identify gaps: scenarios that do not map cleanly to any existing pattern section
- [ ] **4.3** Add new pattern entries to `bola_patterns.md` for any unclassified or emerging patterns found in `generate_data.py` (e.g. single-user permission escalation, temporary-ID hijacking, export-job enumeration, draft-resource access, subscription event hijacking)
- [ ] **4.4** Add Section 10: **Single-User Authorization Expansion** — covers the case where one authenticated user extends their own expected permissions by manipulating IDs, parameters, or states in their own session (no second account needed to exploit)

---

## Phase 5 — Remove All Hardcoded Examples from generate_data.py

- [ ] **5.1** Delete all hardcoded `SCENARIOS`, `ADVERSARIAL_EXAMPLES`, `_LARGE_CONTEXT_EXAMPLES`, `_SALESFORCE_EXAMPLES` (and any other static example lists/dicts) from `generate_data.py` — they are narrow, biased, and context-poor
- [ ] **5.2** Replace example-driven generation with **prompt-driven generation**: each data point is synthesised from the pattern taxonomy + a randomly sampled scenario seed (domain, protocol, object type, vulnerability class) — no more hand-written templates
- [ ] **5.3** Ensure the new generation loop still satisfies the distribution validator (`_validate_distribution`): long-context ratio ≥ 20%, all protocol types covered, all vulnerability families represented
- [ ] **5.4** Preserve and improve `_build_rich_target` (evidence citations, investigation trace, disambiguation) — this is _output format_, not a bias source

---

## Phase 6 — Self-Comparison Manual Test Step

- [ ] **6.1** Create `scripts/run_self_comparison_test.py`: for each test fixture, (a) let the live tool answer the query, (b) call the Qwen model directly with the same prompt + doc as context, (c) compare outputs on structured dimensions (path grounding, finding count, verification completeness, disambiguation), save results to `docs/self_comparison_results/`
- [ ] **6.2** Create `scripts/analyse_comparison_gaps.py`: read comparison results, score each dimension, identify systematic gaps, output a `docs/training_improvement_recommendations.md` with specific prompt changes and, where prompt changes are insufficient, a fine-tuning plan with labelled improvement examples
- [ ] **6.3** Integrate the self-comparison step into `run_three_cycle_retrain_loop.py` after the manual-tests stage: cycle passes only if the self-comparison delta is below a threshold (default: ≤ 3 significant discrepancies per fixture)
- [ ] **6.4** Update `run_three_cycle_retrain_loop.py` to read `training_improvement_recommendations.md` and automatically apply prompt patches before the next cycle's data-regeneration step

---

## Phase 7 — Training Data: Explanation of How Results Were Achieved

- [ ] **7.1** In `generate_data.py`, add a `"reasoning_trace"` field to every training example: a step-by-step explanation of *why* the finding was identified (evidence from doc → pattern match → vulnerability class → confidence)
- [ ] **7.2** In `ai_teacher_prompts.py`, update `EXPECTED_RESPONSE_PROMPT` to require an explicit `## How This Finding Was Identified` section after `## Rationale`, detailing the chain of evidence
- [ ] **7.3** Update the eval scorer (`scripts/eval_security_agent_model.py`) to check for presence and quality of the chain-of-evidence section

---

## Phase 8 — Temporary Documentation Cleanup

- [ ] **8.1** Delete the following stale/temporary docs (keep only `MASTER_PLAN.md` as the active plan):
  - `docs/ADVANCED_SECURITY_TRAINING_REFACTOR_EXECUTION_PLAN_20260407.md`
  - `docs/CONTINUOUS_IMPROVEMENT_EXECUTION_PROTOCOL_20260407.md`
  - `docs/CORRECTNESS_FIRST_EXECUTION_PLAN_20260407.md`
  - `docs/DOCUMENTATION_CYCLE_SYNC_20260406.md`
  - `docs/QLORA_LORA_REFACTOR_TASK_TRACKER_20260407.md`
  - `docs/SMALL_MODEL_TRAINING_QLORA_LORA_REFACTOR_PLAN_20260407.md`
  - `docs/TRAINING_EXECUTION_TRACE_20260407.md`
  - `docs/TRAINING_RUNBOOK_QLORA_LORA.md`
  - `docs/e2e_loop_baseline_pre_retrain_20260407.json`
  - `docs/e2e_loop_loop1_procurement_20260407.json`
  - `docs/e2e_loop_loop2_procurement_20260407.json`
  - `docs/e2e_loop_post_retrain_validation_1_20260407.json`
  - `docs/three_cycle_retrain_live_heartbeat_20260407.json`
  - `docs/three_cycle_retrain_status_20260407.json`
  - `docs/MODEL_PROMOTION_GATES.md`
  - `docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md`
  - `docs/ANALYSIS_E2E_GROUNDING_GAP.md`
- [ ] **8.2** Keep permanently: `GOALS.md`, `ARCHITECTURE.md`, `MEMORY.md`, `AGENT_WEAK_PLACES.md`, `AI_MODEL_TEACHING_PLAN.md`, `E2E_TESTING.md`, `ISSUES.md`, `OFFLINE_DEPLOY.md`, `PERFORMANCE_TESTING.md`, `AGENT_PROMPT_FULL_CYCLE.md`, `MASTER_PLAN.md`

---

## Phase 9 — Regenerate All Training Data

- [ ] **9.1** Run `python src/training/generate_data.py --output data/training/ --clean` to delete old data and regenerate from scratch using the new prompt-driven approach
- [ ] **9.2** Validate distribution with `_validate_distribution()`: long-context ≥ 20%, all 9 vulnerability families, all protocols, all bola_patterns.md sections covered
- [ ] **9.3** Run `python scripts/build_training_splits.py` to rebuild SFT / DPO / eval splits
- [ ] **9.4** Verify DPO pairs have updated chosen/rejected format (no User A/B biased examples, reasoning traces present)

---

## Phase 10 — Train Qwen2.5-Coder-3B-Instruct From Scratch

- [ ] **10.1** Kill any running loop; clear old adapter checkpoints from `models/` and `data/training/distilled/`
- [ ] **10.2** Run the three-cycle loop targeting **only** `Qwen/Qwen2.5-Coder-3B-Instruct` with extended timeouts:
  ```
  python scripts/run_three_cycle_retrain_loop.py \
    --track lora16 \
    --base-url http://localhost:8000 \
    --required-consecutive-passes 3 \
    --max-cycles 9 \
    --max-steps 200 \
    --max-train-samples 5000 \
    --retrain-timeout-sec 14400 \
    --e2e-timeout-sec 1800 \
    --manual-timeout-sec 1200 \
    --memory-floor-mb 4000 \
    --low-mem-kill-mb 1000
  ```
- [ ] **10.3** Monitor for OOM: if killed, reduce `--max-steps` to 100 and restart
- [ ] **10.4** Confirm 3 consecutive passes in `docs/three_cycle_retrain_status.json`

---

## Phase 11 — Full Docker Push / Pull / Test Cycle

- [ ] **11.1** Build new Ollama model from updated Modelfile: `docker exec <ollama_container> ollama create bola-analyzer -f /Modelfile`
- [ ] **11.2** Tag and push the full Docker image: `docker tag bolaai_api <registry>/bola-analyzer:latest && docker push <registry>/bola-analyzer:latest`
- [ ] **11.3** Tear down existing stack: `docker compose down -v --remove-orphans`
- [ ] **11.4** Pull fresh image and bring up stack: `docker compose pull && docker compose up -d`
- [ ] **11.5** Run full manual E2E test: ingest one real fixture doc, run all 4 manual test cases, confirm `[ALL PASS]`
- [ ] **11.6** Run self-comparison test: `python scripts/run_self_comparison_test.py --fixture tests/fixtures/doc_adversarial_procurement.md` and review output
- [ ] **11.7** Document test results in `docs/MEMORY.md` under a new "Latest deployment validation" section

---

## Execution Order

| Order | Phase | Estimated effort |
|-------|-------|-----------------|
| 1 | Phase 1 (Model lock-in) | 30 min |
| 2 | Phase 2 (Manual testing rewrite) | 45 min |
| 3 | Phase 3 (bola_patterns awareness) | 30 min |
| 4 | Phase 4 (Extend bola_patterns.md) | 45 min |
| 5 | Phase 5 (Remove examples from generate_data.py) | 60 min |
| 6 | Phase 7 (Add reasoning traces) | 30 min |
| 7 | Phase 6 (Self-comparison step) | 60 min |
| 8 | Phase 8 (Temp doc cleanup) | 10 min |
| 9 | Phase 9 (Regenerate data) | 20 min (runs async) |
| 10 | Phase 10 (Train 3B) | 4–8 h (runs async) |
| 11 | Phase 11 (Docker cycle) | 30 min |
