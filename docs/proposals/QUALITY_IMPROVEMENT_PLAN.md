# Quality Improvement Plan — BOLA AI Response Quality

**Created:** 2026-05-12  
**Status:** IN PROGRESS  
**Goal:** Eliminate response bias (Actor A/B tunnel vision), achieve broad multi-class vulnerability coverage, grounded curl examples, diverse verified training data, and a deployable validated image.

---

## Progress Ledger

| Phase | Status | Notes |
|-------|--------|-------|
| 0. Architecture implementation check | DONE | 193 tests pass, all new modules import clean |
| 1. Training methodology research | DONE | 6 approach docs created in training_approaches/ |
| 2A. Prompt-only approach — generate+test | DONE | Implemented gate-based prompt (A+E combined) |
| 2B. CoT instruction tuning | BLOCKED | No GPU/unsloth; examples written for future run |
| 2C. DPO/contrastive | BLOCKED | No GPU/unsloth; examples written for future run |
| 2D. Multi-class diverse SFT — 14 examples generated | DONE | Merged into train.jsonl (717 total) |
| 2E. Two-stage pipeline approach | DOCUMENTED | approach_F_two_stage.md written |
| 3. Cross-approach analysis and combination | DONE | BEST_APPROACH.md written |
| 4A. Vuln type 1 — 8 examples (field-level injection) | DONE | 7 train + 1 holdout |
| 4B. Vuln type 2 — 8 examples (write escalation) | DONE | 7 train + 1 holdout |
| 5. Combined training: 7+7 examples | DONE | combined_train.jsonl (14 lines) created |
| 6. Test 8th from each + combined | PARTIAL | Gate bias eliminated; URL hallucination remains (needs fine-tuning) |
| 6.5. Prompt refine loop until 3 types pass | PARTIAL | Single-user verified; template fill-in blocked by 3B model capacity |
| 7. Curl example prompt refinement | PARTIAL | Method correct; URL grounding needs fine-tuning |
| 8. E2E test + publish + pull + test | DONE | CI success; image pulled; API health ok; analysis completes |

**BLOCKER:** No GPU / no `unsloth` — QLoRA fine-tuning deferred. Prompt improvements applied. Need Docker environment running for live testing.

**PIVOT:** Applied Approach A+E (gate-based prompt + evidence-first + temperature reduction). This is testable immediately once `docker compose up -d` is run.

---

## Phase 0 — Architecture Implementation Check

### Checklist
- [ ] DocEnricher: smoke tests, lint, integration with runner
- [ ] ExampleGenerator: smoke tests, lint
- [ ] prompts_examples.py: all API type detectors tested
- [ ] runner.py: _run_har_pipeline passes source_filter correctly
- [ ] report_renderer.py: enriched/examples kwargs render correctly
- [ ] Run full pytest suite; 0 new failures

---

## Phase 1 — Training Methodology Research

### Approaches to evaluate

**Approach A: Prompt engineering only (no fine-tuning)**  
- Best current system prompt + user prompt, zero training changes.
- Pro: instant iteration, no GPU cost.
- Con: small model may not follow complex instructions consistently.
- Test metric: does model follow priority order (field-level first)?

**Approach B: Chain-of-thought (CoT) instruction tuning**  
- Each training example has explicit reasoning chain: "Step 1 — check field injection... Step 2 — check write escalation... Step 3..."
- Forces model to reason before concluding.
- Pro: improves reasoning on ambiguous cases, reduces bias.
- Con: longer outputs, more token budget needed.

**Approach C: DPO / contrastive pairs (chosen/rejected)**  
- Each example has a good response (chosen) + a bad response (rejected, e.g. "Actor A vs Actor B" when not needed).
- Directly penalises the tunnel-vision bias.
- Uses bola_har_specialist_dpo.jsonl format.

**Approach D: Multi-class diverse SFT**  
- 8 training examples per vulnerability class (not just BOLA).
- Covers: field injection, write escalation, batch BOLA, rate-limit bypass, GraphQL traversal, mass assignment, lifecycle bypass, cache-key mismatch.
- Pro: forces model to pattern-match multiple classes.

**Approach E: Structured output + evidence-first**  
- System prompt forces model to cite evidence BEFORE making claims.
- Evidence block → finding block → verification block (never in reverse).
- No training needed; pure prompt re-ordering.

**Approach F: Two-stage pipeline (prompt-only)**  
- Stage 1: triage prompt (list candidate endpoints, 200 tokens max).
- Stage 2: deep analysis prompt per candidate.
- Pro: reduces hallucination by narrowing focus.
- Con: doubles LLM calls, slower.

### Evaluation rubric (fill per approach per example)

| Parameter | Score (1-5) | Notes |
|-----------|-------------|-------|
| Priority order followed | | field-level before cross-principal? |
| Evidence grounding | | facts from context only? |
| Single-user-first | | avoids 2-token test when 1 suffices? |
| Hallucinated endpoints | | zero = 5 |
| Curl correctness | | method, headers, body correct? |
| Vulnerability class breadth | | only BOLA or multi-class? |
| Response format compliance | | matches output format? |
| Secure/vulnerable outcome clarity | | both defined? |
| No bias / no tunnel vision | | not always "Actor A vs Actor B"? |
| Actionability | | auditor can execute immediately? |

---

## Phase 2 — Per-Approach Example Generation and Testing

### For each approach:
1. Write 8 training examples **one by one** (no scripts) as individual JSONL lines.
   - Each example: different domain (fintech, health, gov, aerospace, logistics, legal, energy, telecom).
   - Each example: different vulnerability class from the taxonomy.
   - Documents must NOT give hints (no "RISK-xxx: pattern detected here" labels).
2. Fine-tune base model with examples 1-7.
3. Test with example 8 (holdout).
4. Fill evaluation rubric.
5. Refactor system/user prompt, retest on same example 8.
6. Document delta in rubric.

### Vulnerability class assignments (8 per set, no repetition in a set)
| # | Class | Priority |
|---|-------|----------|
| 1 | Field-level authorization injection | P1 |
| 2 | Write escalation / mass assignment | P2 |
| 3 | ID swap (object enumeration) | P3 |
| 4 | Cross-principal (two-user) — justified case | P4 |
| 5 | GraphQL resolver traversal injection | P5 |
| 6 | Rate-limit bypass / brute-force | P6 |
| 7 | Lifecycle state bypass | P5 |
| 8 | Cache-key authorization mismatch | P5 |

---

## Phase 4 — Dedicated Vulnerability Type Examples

### Vuln type 1: Field-level authorization injection (P1, single-user)
- 8 examples, 8 different domains, same document structure.
- Document structure: OpenAPI/REST API, authenticated user, `fields` or `$select` query parameter, no field-level permission check.
- No labels, no hints. Model must identify the field injection risk from the API shape alone.

### Vuln type 2: Write escalation (P2, single-user)
- 8 examples, 8 different domains.
- Document structure: REST POST/PATCH, request body accepts `role`, `status`, `owner_id`, or `tier` fields that are not server-validated.
- No labels, no hints.

---

## Phase 5 — Combined Training

- Train base model on 7 from Vuln type 1 + 7 from Vuln type 2 simultaneously.
- Use best approach identified in Phase 3.
- Save checkpoint.

---

## Phase 6 — Testing and Prompt Iteration Loop

**Test set:**
1. Holdout example 8 from Vuln type 1 (field-level injection)
2. Holdout example 8 from Vuln type 2 (write escalation)
3. Combined example: same document, both vulnerability types present simultaneously

**Success criteria per test:**
- Identifies correct vulnerability class (not defaulting to cross-principal).
- Evidence citations match artifact.
- Verification strategy uses ONE token (not two) for P1/P2 findings.
- No hallucinated endpoints.
- Curl command is correct and copy-pasteable.

**Loop:**
1. Run test → fill rubric.
2. Identify worst-scoring parameter.
3. Refactor prompt addressing that parameter.
4. Retest.
5. Save result with prompt version (prompt_v1.md, prompt_v2.md, ...).
6. Repeat until all three test cases score 4+ on all rubric parameters.
7. Try combining best prompts from different versions.
8. Mark final best prompt.

---

## Phase 7 — Curl Example Prompt Refinement

**Focus:** model must produce copy-pasteable curl commands for ANY finding type.

**Test cases:**
- P1 field injection curl (GET with extra fields parameter)
- P2 write escalation curl (PATCH with extra attributes)
- P3 ID swap curl (GET/DELETE with foreign ID)
- GraphQL curl (POST /graphql with mutation)

**Rubric:**
- Correct HTTP method
- Correct URL (from artifact, no hallucination)
- Correct headers (Authorization, Content-Type, tenant headers if present)
- Correct body (P1: fields array, P2: escalated attributes, P3: swapped ID)
- Two variants where needed (own resource + foreign resource)

---

## Phase 8 — Deploy and Validate

1. `git push` to trigger GitHub Actions publish.
2. Wait 15 minutes for image build.
3. `docker pull ghcr.io/igorredkach/bolai:latest`
4. Run E2E test suite against new image.
5. If failures: identify root cause, fix, push again.
6. Repeat until E2E passes.

---

## File Structure for This Plan's Artifacts

```
docs/proposals/
  QUALITY_IMPROVEMENT_PLAN.md          ← this file
  training_approaches/
    approach_A_prompt_only.md          ← prompt text + rubric results
    approach_B_cot.md
    approach_C_dpo.md
    approach_D_multi_class.md
    approach_E_evidence_first.md
    approach_F_two_stage.md
    BEST_APPROACH.md                   ← final decision + reasoning
  prompts/
    prompt_v1.md
    prompt_v2.md
    ...
    prompt_best.md
data/training/sft/quality_improvement/
  vuln_type1_field_injection/
    examples_1_7.jsonl                 ← training set
    example_8_holdout.jsonl            ← holdout
  vuln_type2_write_escalation/
    examples_1_7.jsonl
    example_8_holdout.jsonl
  combined_train.jsonl                 ← merged 7+7
  combined_test_example.jsonl          ← both vulns in one doc
```

---

## Blocking Conditions

- Training environment not available (no `unsloth` / no GPU) → fall back to prompt-only approaches (A, E, F) and document
- Docker build fails → fix pipeline errors first
- E2E failures after deploy → file as issue, fix, redeploy

---

## Anti-Bias Design Rules for All New Examples

1. **No "Actor A" / "Actor B" framing unless P4 (cross-principal) is the CORRECT class.**
2. **P1/P2/P3 findings require ONE authenticated session — never add a second user.**
3. **Documents must not label vulnerabilities** — no "RISK-xxx: pattern X found here".
4. **Each example must have a different domain** — no two examples in the same industry.
5. **Curl commands must use real artifact values** — URL, headers, field names all from the document.
6. **Vulnerable outcome must be specific** — not "data returned" but "field X returned with value Y".
