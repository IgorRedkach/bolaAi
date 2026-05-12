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

## Rubric Results

| Parameter | Before (v0) | After prompt refactor | Notes |
|-----------|-------------|----------------------|-------|
| Priority order followed | | | |
| Evidence grounding | | | |
| Single-user-first | | | |
| Hallucinated endpoints | | | |
| Curl correctness | | | |
| Vulnerability class breadth | | | |
| Response format compliance | | | |
| Secure/vulnerable outcome clarity | | | |
| No bias / no tunnel vision | | | |
| Actionability | | | |

**Example 8 holdout result:** TBD  
**Best prompt version for this approach:** TBD  
**Verdict:** TBD
