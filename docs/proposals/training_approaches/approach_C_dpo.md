# Approach C — DPO / Contrastive Pairs (Chosen / Rejected)

**Hypothesis:** The core bias problem is that the model has seen too many cross-principal (Actor A / Actor B) examples during training or pre-training, so it defaults to that pattern even when it is wrong. DPO (Direct Preference Optimization) directly penalises the unwanted behavior by showing:
- **Chosen:** correct single-user analysis for a P1/P2 finding.
- **Rejected:** the same artifact but with an Actor A vs Actor B response (wrong class for this evidence).

**How it works:**
- DPO loss pushes the model toward `chosen` and away from `rejected`.
- This is more efficient than pure SFT for "unlearning" biases in small models.
- We already have `bola_har_specialist_dpo.jsonl` (10 examples) — extends this file.

**Training example structure (JSONL):**
```jsonl
{
  "prompt": "### Instruction\nAnalyze...\n\n### Context\n{doc_with_field_injection_only}\n\n### Response\n",
  "chosen": "## Findings\n### Field-level injection...\ncurl -X GET ... ?fields=email,role,secret_salary\nExpected vulnerable: secret_salary value returned.",
  "rejected": "## Findings\n### Cross-principal access...\ncurl with Token A...\ncurl with Token B...\nIf Token B receives Token A's data..."
}
```

**Design rules:**
- `rejected` must be a PLAUSIBLE-SOUNDING bad response (not gibberish).
- The rejected response must use the WRONG vulnerability class for the evidence.
- For P1 artifacts → rejected uses P4 (cross-principal).
- For P4 artifacts → rejected uses P1 (field injection when evidence shows cross-tenant).

**Limitation:** DPO requires a separate training pass from SFT. Small models sometimes collapse on DPO if chosen/rejected rewards are too similar. Need `beta=0.1` (low) to avoid collapse with 3B.

---

## Rubric Results

| Parameter | Score (1-5) | Notes |
|-----------|-------------|-------|
| Priority order followed | | |
| Evidence grounding | | |
| Single-user-first | | |
| Hallucinated endpoints | | |
| Curl correctness | | |
| Vulnerability class breadth | | |
| Response format compliance | | |
| Secure/vulnerable outcome clarity | | |
| No bias / no tunnel vision | | |
| Actionability | | |

**Example 8 holdout result:** TBD  
**Best prompt version for this approach:** TBD  
**Verdict:** TBD
