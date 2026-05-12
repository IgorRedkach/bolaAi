# Approach F — Two-Stage Pipeline (Triage + Deep Analysis)

**Hypothesis:** Asking a 3B model to simultaneously: (1) read a large document, (2) identify all interesting endpoints, (3) classify the vulnerability type, (4) write verification steps, and (5) produce curl commands — all in one pass — overloads it. Breaking this into two small focused LLM calls (triage, then analysis) should substantially improve quality on each sub-task.

**Stage 1 — Triage (low budget, fast):**
```
System: You are a security triage filter. Given an API artifact, list ALL endpoints and fields 
that could have authorization problems. Be exhaustive. Output a JSON list only.
Output: [{"endpoint": "GET /api/users", "risk": "fields param, no auth validation"}, ...]
```
Token budget: 200 output tokens. Fast.

**Stage 2 — Deep analysis (one candidate at a time):**
```
System: You are a security analyst. Given one candidate finding, determine the exact vulnerability 
class, write ONE precise verification curl, define secure vs vulnerable outcome.
Input: {"endpoint": "GET /api/users", "risk": "fields param, no auth validation", "context": {excerpt}}
Output: [structured finding with curl]
```
Token budget: 400 output tokens per candidate.

**Implementation:** New `_run_two_stage_analysis()` in runner.py. Uses `bola-analyzer` for both stages.

**Pro:** Each stage is simpler. Model doesn't need to hold entire document in context for stage 2 (only the excerpt).  
**Con:** 2x LLM calls. For CPU inference at 5-8 tok/s, adds ~30-60s per candidate.

**Combination potential:** F + D (multi-class training) — train stage 1 triage model separately, stage 2 analysis model with diverse class examples.

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
