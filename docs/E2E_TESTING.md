# E2E Testing (Real LLM)

E2E tests **talk to the real LLM** via the API and **assert on the content of the report**, not just HTTP status codes. They verify that:

1. The stack is running with Ollama and the `bola-analyzer` model.
2. Ingested documentation is used as context.
3. The LLM returns BOLA-focused findings.
4. The LLM provides **verification steps** (concrete instructions for auditors).

## What we test

- **test_llm_report_references_ingested_documentation** — We ingest sample project docs (see `tests/fixtures/sample_project_documentation.md`). The report must reference at least one resource/endpoint from that doc (e.g. patient, order, prescription, `/api/`). This proves the LLM read our input.
- **test_llm_report_contains_verification_steps** — The report must contain the word "verification" or "step" and concrete instructions (e.g. "call", "token", "with two different user").
- **test_llm_report_is_bola_focused** — The report must contain at least two BOLA-related terms (e.g. BOLA, ownership, authorization, access, permission).
- **test_llm_report_is_not_error_or_generic** — The report must be long enough, have structure (headings/lists), and not be an error message.

If the API or Ollama is not available, the E2E tests are **skipped** (they do not fail the suite).

## Sample project documentation

The file `tests/fixtures/sample_project_documentation.md` is a short, realistic project doc that describes:

- A "HealthHub" API with patients, orders, prescriptions, and internal cases.
- Intentional BOLA red flags: no documented ownership or permission checks for object IDs, linked `case_team_members` without access rules, logs/queue visibility.

We ingest this doc and ask the LLM for BOLA findings and verification steps. The tests then assert that the **LLM output** mentions these resources and includes verification steps.

## How to run E2E

1. **Start the stack with the model** (so the LLM is actually running):

   ```bash
   # Offline: model must already be in volume.
   docker compose -f docker/docker-compose.yml up -d

   # Or one-time online setup to load the model:
   OLLAMA_ONLINE_SETUP=1 docker compose -f docker/docker-compose.yml up -d
   ```

2. Wait until the API and Ollama are ready (e.g. `curl http://localhost:8000/health` shows `"ollama": true`).

3. **Run the E2E tests** (they hit the live API and assert on report content):

   ```bash
   BOLA_AI_LIVE_URL=http://localhost:8000 PYTHONPATH=src pytest tests/test_e2e_llm.py -v -s
   ```

   Use `-s` to see print output and report excerpts if a check fails.

4. Optional: run the live API QA script first to confirm health/ingest/analyze work:

   ```bash
   sh scripts/qa_api_live.sh http://localhost:8000
   ```

## Expectation: LLM is running

When the LLM is running, you should see:

- **Memory:** The process that runs the analyze request (Ollama or the app) may show a **memory spike** during analysis (model inference).
- **Latency:** `/analyze` takes tens of seconds (e.g. 30–90 s) per request, not milliseconds.
- **Content:** The report is long (hundreds to thousands of characters), mentions your endpoints/resources, and includes verification steps and BOLA-related wording.

If E2E tests are **skipped**, the health check failed or `ollama` was not `true` — start the stack and ensure the model is loaded. If tests **fail** on content assertions, the report did not meet the criteria above (e.g. model not loaded, wrong model, or prompt/context issue).

## Issue-resolution tests

Open issues and their acceptance criteria are tracked in [docs/ISSUES.md](ISSUES.md). Each issue has an autotest in `tests/test_issues_resolved.py`. When an issue is fixed, mark it PASSED in ISSUES.md; the corresponding test should then pass when run against the live API:

```bash
BOLA_AI_LIVE_URL=http://localhost:8000 PYTHONPATH=src pytest tests/test_issues_resolved.py -v -s
```

## Manual communication test loop

After each code or prompt change, **talk to the application** (not only run autotests) to catch issues the tests might miss:

1. **Start the stack** (if not already running): `docker compose -f docker/docker-compose.yml up -d` (from `docker/`).
2. **Ingest and analyze:** Ingest the sample doc, then call `POST /analyze` with a clear query (e.g. "Identify BOLA risks and give verification steps.").
3. **Read the full report:** Inspect the response for:
   - Duplicate headings (`### ###`), hallucinated endpoints (`/api/users/`, `/api/tenants`, paths not in the doc), missing two-token verification phrasing, or rationale that says "no authentication" when the doc requires auth.
4. **If you find issues:** Fix them (prompt, post-processing in `runner._normalize_report`, or tests), run `pytest tests/test_issues_resolved.py`, then **restart the app** (`docker compose restart bola-ai`) and go back to step 2.
5. **Stop** only when a full manual pass finds no issues.

Post-processing in `src/bola_ai/agent/runner.py` (`_normalize_report`) already fixes duplicate headings, appends a two-token verification reminder when missing, redacts common hallucinated paths, and replaces "without a token" with two-token phrasing (Issue 6).

## New manual test cases (multiple docs)

To evaluate the tool on **multiple documentation fixtures** with clear expected outcomes:

1. **Fixtures** (in `tests/fixtures/`): `sample_project_documentation.md`, `doc_ecommerce_orders.md`, `doc_file_storage.md`, `doc_support_tickets.md`, `doc_crm_contacts.md`. Expected outcomes are in `tests/fixtures/expected_outcomes.md`.
2. **Reset before each doc:** The API exposes `POST /reset` to clear the document store so each test case runs with only that doc (no mixing with previous ingests).
3. **Run all manual test cases:**
   ```bash
   BOLA_AI_LIVE_URL=http://localhost:8000 python scripts/run_manual_test_cases.py --timeout 300
   ```
   The script resets, ingests each doc, calls analyze, and evaluates the report (doc-specific context, no hallucinated paths, two-token verification, no "without a token"). Use `--timeout 300` (or higher) so slow LLM responses do not cause timeouts.
