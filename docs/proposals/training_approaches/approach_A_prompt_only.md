# Approach A — Prompt Engineering Only (No Fine-Tuning)

**Hypothesis:** The base model (qwen2.5-coder:3b) with a strong, precisely ordered system prompt can produce acceptable security analysis without any fine-tuning, provided:
1. The priority order is unambiguous and numbered.
2. Each priority explicitly states whether 1 or 2 tokens are needed.
3. Evidence citation is mandatory BEFORE claim.

**Why the current prompt fails:**
- It lists Priorities 1-6 but the language is soft ("does the endpoint accept...").
- The GRAPHQL/AURA next-steps section is very long and may dominate the context window.
- The model likely pattern-matches to the cross-principal template because it appears last and is longest.
- `temperature 0.7` is high for a small model — causes drift.

**Proposed prompt changes (Approach A):**
1. Move P1/P2/P3 templates BEFORE the cross-principal template, with a hard STOP rule.
2. Add a mandatory "CLASSIFICATION GATE" at the start of every response.
3. Reduce temperature to 0.3 for bola-analyzer.
4. Add negative examples inline: "DO NOT write 'Token A / Token B' for field-injection findings."

**Testable claim:** Changing only the Modelfile (temperature + system prompt) should move rubric scores from ~2 to ~3.5 on priority-order compliance without any training.

---

## Rubric Results (Tested 2026-05-12, live model bola-analyzer on CPU)

| Parameter | Before (v0) | After prompt refactor | Notes |
|-----------|-------------|----------------------|-------|
| Priority order followed | 2 | 4 | Gate numbers present; write escalation identified before cross-principal |
| Evidence grounding | 2 | 3 | Evidence table present; URL hallucination from RAG noise |
| Single-user-first | 1 | 5 | "ONE authenticated session" explicitly stated |
| Hallucinated endpoints | 2 | 2 | Still uses `api.example.com/profile` instead of artifact URL; RAG pollution |
| Curl correctness | 2 | 3 | Method correct (PATCH), URL wrong (hallucinated) |
| Vulnerability class breadth | 2 | 3 | Write escalation identified; field injection test also correct in first test |
| Response format compliance | 2 | 3 | Gate template not fully resolved (shows `[Gate Class]` literally) |
| Secure/vulnerable outcome clarity | 3 | 3 | Both defined; secure outcome says "401" instead of "403" |
| No bias / no tunnel vision | 1 | 5 | Zero "Actor A / Actor B" in outputs — MAJOR WIN |
| Actionability | 2 | 3 | Steps present but URL wrong |

**Write escalation test result:** Correctly identified write escalation (payout_status, payout_amount) as the finding; ONE session explicitly stated; no cross-principal; evidence table filled in. Template placeholders not fully resolved — 3B model limitation.

**Field injection test result:** Gate 1 label used; single-user verification stated; but hallucinated a different endpoint from RAG context.

**Best prompt version for this approach:** `prompt_v1_gate_evidence_first.py`

**Verdict:** PARTIAL SUCCESS
- Major win: Actor A / Actor B bias eliminated completely
- Major win: Single-user verification consistently stated for Gate 1/2/3
- Remaining issue: URL hallucination from RAG pulling in irrelevant documents — needs stricter RAG source filtering OR fine-tuning
- Remaining issue: Template not fully resolved (3B model copies template structure verbatim)
- Next step: Fine-tuning with 14 new diverse examples (blocked by GPU) will fix both remaining issues
