# E2E Testing (always live)

Runs after pytests and any manual test scripts when you are doing full quality sign-off.

**Agent quality loop:** Full-cycle agents follow **`docs/AGENT_PROMPT_FULL_CYCLE.md`**, track weak spots in **`docs/AGENT_WEAK_PLACES.md`**, and continue until registry + ISSUES are clear (see **`docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md`**).

**E2E is always live:** Tests that hit the real API + LLM **do not silently skip** — **`pytest tests/` fails at collection** if the API + Ollama are not reachable at `BOLA_AI_LIVE_URL` (default `http://localhost:8000`). If something fails, file or update an **OPEN** issue, fix it, and re-run the loop.

Quality is validated on the **real** stack, not optional mocks.

---

## MANDATORY: Pre-commit/pre-deploy E2E gate (WP-022)

**NO code change may be committed or pushed without completing a full E2E cycle.** This is non-negotiable. Unit tests passing alone is NOT sufficient. The following must ALL be true before `git commit`:

1. Shared folder cleaned (only `.gitkeep`)
2. Fresh test data generated (new API doc with unique endpoints)
3. Expected risks listed before running
4. Stack restarted or reset + ingest via chat/API
5. Analysis run with per-response R1-R7 checklist
6. Strict coverage verified: every expected risk has matching finding
7. Wider communication: multiple analysis calls including follow-ups, driven by the model's prior answers
8. Web UI verification: all 7 manual checks pass
9. No hallucinated endpoints in any response

**Why this exists:** Agent repeatedly pushed code after unit tests without E2E, leading to 3 production bugs (BUG-003, source filter gap, BUG-004) caught only by the user. See WP-022.

---

## Files that require a live stack

Confirm against current repo layout before you run:

- `tests/test_e2e_llm.py` — LLM report content
- `tests/test_issues_resolved.py` — issue acceptance vs real LLM
- `tests/test_api_live.py` — health, ingest, analyze, UI

Collection guard logic: **`tests/conftest.py`** (`pytest_collection_finish`).

## Before you run pytest

```bash
cd docker && docker compose up -d
PYTHONPATH=src python -m bola_ai.cli health --wait
PYTHONPATH=src pytest tests/ -v
```

If you cannot run live tests, create an **OPEN** issue, stop the current "done" narrative, fix the blocker, and start a new improvement loop.

Live E2E is not skipped by default; if the environment truly cannot run them, document that in open  ISSUES and start a new improvement loop.

---

## Critical: shared folder lifecycle in E2E

Every E2E cycle **must** follow this exact sequence to prevent hallucinated findings:

### 1. Clean shared folder
Remove ALL files from `shared_docs/` (the host-side folder) **before** starting the stack. Only `.gitkeep` should remain.

```bash
rm -f shared_docs/*.md shared_docs/*.txt shared_docs/*.har
ls shared_docs/   # should show only .gitkeep
```

### 2. Generate fresh test data
Either pick an existing fixture from `tests/fixtures/` or generate a new one. The test document must contain specific, unique API endpoints so you can verify the tool references **your** document and not generic training data.

**Diversity rule (mandatory):** Across loops, rotate test data types and domains. Do not run Salesforce-only or HAR-only cycles repeatedly. Include mixed systems/doc styles (REST docs, GraphQL/SOQL-aware docs when applicable, and HAR/network-log style inputs) from different domains.

### 3. Copy to shared_docs/ and start (or restart) the stack
```bash
cp tests/fixtures/doc_banking_api.md shared_docs/
docker compose restart bola-ai   # triggers auto-ingest on startup
```

Or, if the container is already running, use the chat:
```
You: ingest
Bot: Ingested 1 file(s) from shared_docs/ (N total chunks): ...
```

### 4. Verify auto-ingest happened
```bash
curl -s http://localhost:8000/health | python -m json.tool
```
Check that `user_documents` > 0 and `user_doc_sources` lists your file(s).

### 5. Verify analysis guard works
Before ingesting (or after reset), any analysis question should return a `type: "info"` response saying "No documents have been ingested yet" — NOT an analysis. This prevents hallucination from generic training data.

---

## What we assert (live LLM) — goals for any E2E pass

0. **Per-response logical correctness (mandatory for every step)**  
   After every `POST /analyze` call, verify the response logically answers the question asked — not just that it contains text. Question type determines the expected response shape:

   | Question type | Expected shape | Failure signal |
   |---|---|---|
   | Runbook / numbered steps | Numbered list (1. 2. 3. …) present | No `\d+\.` lines found |
   | Curl generation (q5) | ≥2 `curl` commands, token_A and token_B | Fewer than 2 curl blocks, or only one token |
   | Path audit (q6) | YES/NO entries for each cited path | No YES/NO or `->` entries |
   | Request generation | `curl` with method and `Authorization` header | Missing curl or missing auth header |
   | Security analysis | Finding headings (`###`) or path + rationale | No paths and no rationale language |
   | Outcome interpretation | Explanation of both 200 and 403 | One or both outcomes missing |

   `scripts/run_agent_e2e_loop_once.py` runs `_check_logical_correctness(query, report)` for every step and reports failures in the `automated_checks.logical_correctness_summary` field of the output JSON. Any `logical_match: false` entry **must** be investigated and logged as an OPEN issue if it is a repeatable tool failure.

1. **Fresh documentation every meaningful E2E cycle**  
   Generate new test documentation from scratch for that run: think through the **system under test**, **plausible vulnerability angles**, and **what you expect** the tool to surface before you write the doc.  
   **Required intake path:** copy the doc into the shared Docker docs path (`shared_docs` on host, mounted to `/shared-docs` in container), then either let auto-ingest handle it on startup, or say "ingest" in the chat after **`reset`**.

2. **Analysis requires user documents**  
   The tool must **refuse** to run analysis if no user documents are ingested. It must show a message listing available files and how to ingest them. This is the guard against hallucinated findings from generic training data.

3. **Reports match tool goals**  
   Responses should include **actionable verification steps** across relevant vulnerability classes and stay **grounded** in the ingested doc (paths, methods, no invented GraphQL/SOQL when the doc is REST-only, etc. — see **`docs/GOALS.md`**).

4. **Answers are grounded in generated data**  
   After ingesting your test doc, verify that:
   - Endpoints mentioned in the report **exist** in your test document
   - The tool does NOT mention endpoints from other fixtures or training data
   - Verification steps reference the correct HTTP methods and paths from YOUR doc

5. **Primary method: adaptive person-style E2E (not "the script = the test")**  
   Think about possible questions a person can ask for more details and support according to the generated context. Evaluate after each tool response. And verify responses according to the expectations you believe are correct for the context.

   **How adaptive E2E should work:**

   | Step | What you do |
   |------|----------------|
   | **Clean shared folder** | Remove all files except `.gitkeep`. |
   | **Start the stack** | Docker up, health OK. |
   | **Verify guard** | Ask a security analysis question — should get "No documents ingested" response. |
   | **Pass generated data** | Copy doc to `shared_docs/`. Say "ingest" in chat (or restart for auto-ingest). |
   | **Verify ingest** | Check health endpoint: `user_documents` > 0. |
   | **First request** | One analysis question tied to that doc. |
   | **Read the answer** | Judge it against **your scenario**: coverage, grounding, verification logic. |
   | **Next request from context** | Ask a **new** question **informed by what the model just said**. |
   | **Repeat** | Continue until satisfied the tool has been exercised enough. |
   | **Per-response analysis** | For **every** response: grounded? vulnerability-relevant? verification sound? |

6. **Improvements become work items**  
   Anything that should change product or process → **`docs/ISSUES.md`** and/or **`docs/GOALS.md`**.

---

## Scripted smoke is support only (not a substitute for adaptive E2E)

`scripts/run_agent_e2e_loop_once.py` runs a baseline multi-question flow. Use it to **regress** grounding and follow-up shape; **still** run adaptive person-style passes when you care about depth.

When `BOLA_AI_E2E_FIXTURE` is **not** set, the script auto-selects fixtures using diversity rotation and records the selection metadata in `docs/e2e_loop_last_run.json`.

The script now:
1. Cleans `shared_docs/` before starting
2. Stages the fixture into `shared_docs/`
3. Verifies auto-ingest or explicitly ingests via chat
4. Verifies answers reference the ingested document's endpoints

Log output: **`docs/e2e_loop_last_run.json`**.
Release sign-off = full **`pytest tests/`** with stack up.

---

## Manual web verification (mandatory in every E2E cycle)

After API-level E2E completes, verify the **interactive web chat** works:

1. **Open `http://localhost:8000/chat`** in a browser (or use browser automation).
2. **Verify page loads:** Header shows "BOLA AI" with a green status dot. Welcome message is visible. Status shows user doc count.
3. **Test "help" command:** Type `help` and send. Verify the usage guide appears with sections: Getting Started, Commands, Example Conversation, Tips.
4. **Test analysis guard:** After reset, type a security analysis question. Verify you get "No documents have been ingested yet" (NOT an analysis).
5. **Test broad ingest phrases:** Type "get the files" or "investigate my documents" or "take a look". Verify bulk ingest is triggered.
6. **Test analysis question:** Type a security analysis question. Verify the response references endpoints from the ingested document.
7. **Test "status" command:** Type `status`. Verify system info includes user document count and source names.

**Pass criteria:** All 7 steps succeed. The chat UI renders markdown correctly, auto-scrolls, and the loading spinner appears during analysis.

If any step fails, file an **OPEN** issue in `docs/ISSUES.md` and fix before claiming E2E completion.

---

## Mandatory publish/pull verification (runtime issues)

When a loop fixes runtime problems (timeouts, startup contention, deployment regressions), this is mandatory before closure:

1. Push changes so CI publishes a new image.
2. Delete local BOLA containers and images.
3. Pull the newly published image.
4. Run from scratch with shared docs volume.
5. Verify `/health`, `/chat`, and one interactive analysis request.

This prevents "works in source tree but not in pulled image" regressions.

### Completion blocker (new)

If the cycle touches runtime behavior (`src/bola_ai/api/**`, `src/bola_ai/agent/**`, `docker/**`, startup/ingest/analyze orchestration, or E2E runner scripts), release/loop completion is blocked until:

1. Changes are pushed to remote.
2. CI image build for that pushed SHA is successful.
3. Pulled image digest is recorded from local `docker inspect`.
4. Pulled image is run from scratch with cleaned shared docs.
5. Manual chat verification passes.

If any step above is not possible, the cycle must be reported as **OPEN/BLOCKED** (not complete) with explicit blocker evidence.
