# Full Quality Cycle — Agent Prompt

Use this prompt with another model to reproduce the full quality-improvement loop for the BOLA AI tool.

---

You are a coding agent working in my local repo. Your job is to run a full quality-improvement loop for a local-only BOLA AI tool and stop only when there are no new issues.

## Project context

- **Goal:** Free, local-only, offline-capable AI security tool focused on BOLA.
- **Must be auditor-friendly:** Concrete, valid verification steps.
- **Runtime must not require open internet.**
- **Stack:** FastAPI + Chroma RAG + Ollama model in Docker.
- **I want behavior quality, not only passing tests.**

## Hard requirements

1. **Read and use goals as source of truth:**
   - `docs/GOALS.md`
   - `docs/ISSUES.md`

2. **Work in loops until no new issues:**
   - analyze → refactor if needed → update training data → retrain/adapt → run tests → manual API communication → log/fix issues → repeat.

3. **If you find any quality problem, add it to `docs/ISSUES.md` with:**
   - description
   - acceptance
   - autotest name
   - status updates (OPEN → PASSED)

4. **If you identify missing quality criteria, update `docs/GOALS.md`.**

5. **Keep memory-safe execution:**
   - monitor memory during long runs
   - avoid runaway processes
   - prefer low-memory test mode where appropriate.

## Execution plan (do in order)

### A) Baseline audit

- Read:
  - `docs/GOALS.md`
  - `docs/ISSUES.md`
  - `src/bola_ai/agent/runner.py`
  - `src/bola_ai/agent/prompts.py`
  - `src/bola_ai/rag/chunking.py`
  - `src/training/generate_data.py`
  - `src/training/load_knowledge.py`
  - `tests/test_issues_resolved.py`
  - `tests/test_agent.py`
  - `scripts/run_manual_test_cases.py`
- Compare implementation to goals. Note any gaps.

### B) Refactoring and robustness

- Refactor only where it improves maintainability/behavior/reliability.
- Keep behavior backward compatible unless fixing a bug.
- Add/adjust tests for every bug fix.
- Run lint/diagnostics after edits.

### C) Training/adaptation cycle

- Improve training data quality if needed:
  - Expand realistic BOLA scenarios in `generate_data.py`
  - Ensure JSONL output format is clean and consistent.
- Regenerate training files.
- Reload RAG knowledge.
- Ensure loading does not duplicate endlessly (prefer reset-before-load behavior, configurable by env var).
- Recreate/update Ollama model from Modelfile.

### D) Automated testing

- Run unit tests first (low memory mode where possible).
- Run issue-resolution live tests.
- If failures occur, fix immediately and rerun until green.

### E) Manual API communication (critical)

- Start/restart stack.
- Generate **NEW** documentation fixtures from scratch (do not only reuse existing docs), including adversarial/ambiguous docs:
  - legacy endpoints mentioned but inactive
  - cross-tenant/cross-agency ambiguity
  - role ambiguity (admin/auditor/manager)
  - mixed endpoint versions
  - **GraphQL**: schema with queries/mutations taking object IDs (user(id), document(id)); nested resolvers (User { orders }); batch operations
  - **SOQL/Salesforce**: SOQL examples without WITH SECURITY_ENFORCED; cross-object subqueries; sharing model ambiguity
- For each doc:
  - reset store
  - ingest via API
  - analyze via API with multiple queries
  - evaluate response quality, not just status codes.

**Validation criteria for each response:**

1. Grounded to ingested doc endpoints/resources.
2. No hallucinated unrelated endpoints.
3. BOLA-focused (object-level authorization), not generic auth-only.
4. Verification logic must be valid:
   - Do NOT claim BOLA confirmed from 401/invalid token alone.
   - Do NOT claim BOLA confirmed from 404 alone.
   - Must use two valid user tokens/users against same existing object ID.
5. Output structure should be readable/consistent (no malformed heading patterns).
6. Suggestions must be actionable for an auditor.
7. **GraphQL docs:** Findings must reference operations/fields (e.g. `user(id)`, `deleteDocument(id)`), not only REST paths. Verification steps use GraphQL syntax.
8. **SOQL/Salesforce docs:** Findings must reference record-level risks (WITH SECURITY_ENFORCED, sharing, cross-object queries), not only object-level permissions.

### F) Issue logging and fixes

- Any failed criterion ⇒ create/update issue in `docs/ISSUES.md`.
- Implement fix in code.
- Add autotest reproducing the issue.
- Mark issue PASSED only after test + manual check succeed.
- Repeat full cycle.

### G) Stop condition

Stop only when **ALL** are true:

- No new issues found in latest manual adversarial cycle.
- No OPEN issues left in `docs/ISSUES.md`.
- Tests pass:
  - core/unit tests
  - issue-resolution tests
- Goals are up to date and reflect new quality guardrails discovered.

## Operational constraints

- Do not use destructive git commands.
- Do not revert unrelated user changes.
- Keep logs concise but sufficient.
- Track memory regularly and avoid high-risk commands if memory spikes.
- If Docker/model operations fail, fix and continue autonomously.

## Output format I want from you at the end

1. What gaps were found vs goals.
2. What refactors were done and why.
3. Training data changes (before/after counts + quality improvements).
4. Retraining/adaptation steps executed.
5. New issues added and how each was fixed.
6. Tests run with results.
7. Manual API communication scenarios and quality verdicts.
8. Final statement confirming stop condition reached.
