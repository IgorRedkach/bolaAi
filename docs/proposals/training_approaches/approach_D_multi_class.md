# Approach D — Multi-Class Diverse SFT

**Hypothesis:** The current training data is dominated by one or two vulnerability classes (cross-tenant BOLA and GraphQL traversal). The model has over-indexed on these because they are the most frequent in training. Providing balanced SFT examples — exactly one example per vulnerability class — forces the model to learn distinct detection patterns for each class rather than defaulting to the most common template.

**Class coverage (8 examples, one per class):**
1. P1 — Field-level authorization injection (fields parameter, REST)
2. P2 — Write escalation via mass assignment (POST/PATCH, restricted attributes)
3. P3 — ID swap / object enumeration (path parameter, sequential IDs)
4. P4 — Cross-principal (two-tenant, correct justification for two users)
5. P5 — GraphQL resolver traversal injection
6. P5 — Rate-limit bypass enabling brute-force (X-Forwarded-For spoofing)
7. P5 — Lifecycle state bypass (access draft/archived resources)
8. P5 — Cache-key authorization mismatch (Redis keyed by resource ID only)

**Key design rule:** Each example must be a DIFFERENT industry/domain so the model cannot shortcut by memorizing domain-specific patterns.

**Prediction:** This approach alone is likely to be the highest single-approach improver for "vulnerability class breadth" and "no bias" rubric parameters, but may not improve curl correctness (a separate issue).

**Combination potential:** D + A (prompt refactor) should stack well — diverse training prevents memorization, clean prompt guides generation.

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
