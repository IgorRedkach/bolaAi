# Approach E — Evidence-First Output Structure (Prompt-Only)

**Hypothesis:** The model hallucinates and picks the wrong vulnerability class because it decides the finding FIRST and then searches for evidence. Forcing the output to start with a mandatory "Evidence block" makes it impossible to write a finding without first citing the artifact.

**Proposed output format:**
```
## Artifact Evidence Map
| Section | Observation | Security Relevance |
|---------|-------------|-------------------|
| §3.2 GET /api/users | `fields` query param | No server validation for field names |
| §4.1 POST body | Accepts `role` and `status` | No restriction documented |
| §5.0 HAR | Response includes `salary_band` | Unintended field returned |

## Classification Gate
- P1 (Field injection): YES — fields param, no validation. STOP.
- P2 (Write escalation): YES — role/status in body. Continue.
- P3 (ID swap): No additional evidence beyond P1.
- P4 (Cross-principal): NOT NEEDED — P1/P2 are single-user demonstrable.

## Findings
[only after Evidence Map and Classification Gate are complete]
```

**Why this works for small models:** Evidence-first is a "scratchpad" pattern. The model cannot skip to the conclusion. The Classification Gate is a strict yes/no decision tree that prevents the cross-principal default.

**Implementation:** Change ONLY the system prompt output format section. No training changes.

**Limitation:** Adds ~200 tokens to every response. With 768 token budget, the report section may be truncated. Need to increase num_predict for general analyzer.

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
