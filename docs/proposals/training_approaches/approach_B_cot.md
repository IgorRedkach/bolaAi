# Approach B — Chain-of-Thought (CoT) Instruction Tuning

**Hypothesis:** A small model benefits enormously from being trained to reason step-by-step before concluding. If the training examples show "Step 1: I look for field injection → not found / found because... Step 2: I look for write escalation → found because..." the model learns to audit systematically rather than pattern-match to a memorized template.

**Evidence from literature:** CoT tuning on 7B and smaller models has shown 15-30% improvement on structured reasoning tasks when the training ratio of CoT examples is >50%.

**Training example structure:**
```
### Instruction
Analyze the artifact and identify security vulnerabilities. Check priorities in order.

### Context
{document}

### Response
**Audit trail (internal):**
Priority 1 — Field injection: The endpoint accepts a `fields` query parameter... 
  → Evidence: section 3.2 shows `GET /api/users?fields=email,name,role`. No server-side field permission check documented.
  → FINDING: Field injection possible. Severity: HIGH.

Priority 2 — Write escalation: POST /api/users/:id/profile accepts body...
  → Evidence: section 4.1 body schema includes `role` and `status` fields with no restriction noted.
  → FINDING: Write escalation candidate. Severity: MEDIUM (role accepted without restriction).

Priority 3 — ID swap: path parameter userId...
  → Evidence: no ownership validation documented.
  → No additional finding beyond P1/P2.

Priority 4 — Cross-principal: NOT NEEDED — P1/P2 findings are single-user demonstrable.

**Report:**
[structured findings using P1 evidence, with single-user curl only]
```

**Key difference from current training data:**
- Reasoning chain is explicit and auditable.
- Model learns to EXIT the audit when P1/P2 are found (no cross-principal added unnecessarily).
- Token budget: ~800 for reasoning + ~600 for report = 1400 total. Still fits in 2048 window.

**Limitation:** Training examples are longer. With only 7 examples, overfitting risk is high for a 3B model.

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
