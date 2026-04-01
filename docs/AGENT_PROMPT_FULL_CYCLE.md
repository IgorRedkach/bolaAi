# Full Quality Cycle — Agent Prompt

Use this prompt with another model to reproduce the full quality-improvement loop for the BOLA AI tool.

---

You are a coding agent working in my local repo. Your job is to run a full quality-improvement loop for a local-only BOLA AI tool. **Do not stop and suggest the user run E2E manually.** You must run the tool for real, communicate with it using your own generated test data, and keep improving.

## Weak-place registry + automatic next loop (non-negotiable)

1. **Read `docs/AGENT_WEAK_PLACES.md` at session start.** Any **OPEN** row is **blocking**: you may not report “all done” until that row is **VERIFIED** or legitimately superseded (same gap tracked in ISSUES with stack-only blocker).
2. **Whenever you find a weak spot** (E2E miss, wrong curl method vs doc, grounding hallucination, flaky test, incomplete goal, “minor” polish): **append an OPEN row** to `docs/AGENT_WEAK_PLACES.md` with **acceptance** criteria. **Do not** only mention it in chat — **the registry is the queue.**
3. **Automatic next loop (same session):** After documenting a weak place, you **immediately** start the **next loop**: implement fix → run tests/E2E → re-check registry. **Do not** end your turn with “this could be improved in a follow-up” or “the next run should…”. **You** are the next run until OPEN rows are cleared and stop conditions below hold.
4. **Forbidden as a terminal state:** Ending with any of: *“looks good / could be improved”*, *“reasonable to stop here”*, *“optional next steps”*, *“minor issue”* (without an OPEN row + fix loop), *“proposals for improvement”* without either implementing them **or** converting each into **OPEN** registry rows and then **closing them in subsequent loops in this session**. **If you still have improvement ideas, they are not done — work or register and fix.**

**Continuous loop (mandatory):** **You NEVER stop until there is no job for the next loop.** A “job for the next loop” is **any** of: an **OPEN** row in **`docs/AGENT_WEAK_PLACES.md`**; an **OPEN** issue in **`docs/ISSUES.md`**; an **unresolved** goal or unchecked checklist item you own; **any named improvement or proposal** you have not either **implemented** or **converted to OPEN registry + fixed**; **section E not completed** for the current cycle (stack not exercised with **this cycle’s** new doc, person-style questions, strict coverage check, and step 5 wider communication—if you skipped E or only updated docs, **that is still a next-loop job**); unit/live tests failing; or **strict E2E coverage** not yet verified on **this cycle’s** generated data. **Do not stop** after partial work (e.g. “I updated the prompt” or “docs are done”) if any of the above remains—**continue immediately** with the next step or the next full cycle. Only when **none** of these jobs exist may you stop and report completion.

**Progress notes vs stopping:** You **should** write what is **done so far** (summary, file list, test results) as you work — that helps the user and the next turn. **Writing a progress update is not the end of the job.** After you write what’s done, **keep executing** (fix, test, E2E, close issues, clear weak-place registry) until **`docs/AGENT_WEAK_PLACES.md` has no OPEN rows**, **`docs/ISSUES.md` has no OPEN issues** (for work you own), **`docs/GOALS.md` has no unresolved items** for you, and you have **zero improvement proposals left** (if you can name one, it is a job — implement or OPEN+fix). **Do not stop** only because you produced a good status paragraph.

**Why this exists:** See **`docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md`** for analysis of earlier early-stop behavior.

## Project context

- **Goal:** Free, local-only, offline-capable AI security tool focused on BOLA. This is a **world-class, portable tool** for keeping **critical systems safe** (national interests); quality is non-negotiable.
- **Must be auditor-friendly:** Concrete, valid verification steps.
- **Runtime must not require open internet.**
- **Stack:** FastAPI + Chroma RAG + Ollama model in Docker.
- **Behavior quality, not only passing tests.** **No quality shortcuts:** do not shorten queries, cut content, or relax criteria to make steps “pass”. If something fails or is unacceptable, **analyze the root cause**, **document it as a problem**, and **fix it** in the next loop.
- **Documentation realism:** Treat source docs as potentially incomplete by default (fully complete docs are rare). Keep findings grounded and explicitly call out uncertainty when ownership logic is undocumented.

## Hard requirements

1. **Read and use goals as source of truth:**
   - `docs/GOALS.md`
   - `docs/ISSUES.md`
   - `docs/E2E_TESTING.md`
   - **Do not delete goals in `docs/GOALS.md` unless the user explicitly asks for deletion.** You may edit wording or mark goals as superseded/deprecated, but preserve traceability.

2. **Work in a continuous improvement loop:**
   - Run the tool for real (start/use the stack), generate one-time-use documentation for a fake/possible project, ingest and analyze via the real API, evaluate whether responses are correct and help find problems, identify what is missing or can be improved, add to the learning curve (training data, RAG, prompts) as needed, then repeat. Do not exit the loop by asking the user to run E2E — you run it.

3. **If you find any quality problem, add it to `docs/ISSUES.md` with:**
   - description
   - acceptance
   - autotest name
   - status updates (OPEN → PASSED)

3b. **Failures, interruptions, and unfinished work ⇒ OPEN issues (so the next loop has mandatory work):**
   - If a step **fails** (test red, E2E strict coverage miss, timeout, tool error), you already file or update an issue — keep it **OPEN** until fixed and PASSED.
   - If the **loop is interrupted** (user stop, environment abort, context limit, command killed) **before** you finished section E, D (full tests), or G: **before stopping**, add a new **OPEN** issue titled e.g. **`Agent loop interrupted: <short topic>`** with **Status: OPEN**, what was in progress, what remains (next commands/steps), and **acceptance** for closure. 
   - **You do not need to “prevent” unfinished loops** in advance — you **convert** unfinished or failed work into **OPEN** issues. Any **OPEN** issue, plus **unresolved goals** or **named improvements**, means the **next** agent run **must** do **at least one more loop** to address them. Stopping is only allowed when **no** OPEN issues remain (among those you own), goals satisfied, and section G holds.

4. **If you identify missing quality criteria, update `docs/GOALS.md`.**

5. **Keep memory-safe execution:**
   - monitor memory during long runs
   - avoid runaway processes
   - prefer low-memory test mode for unit tests only; use real stack for E2E.

6. **Reread documentation and guard against hallucination:**
   - **Reread the documentation you maintain** (`docs/GOALS.md`, `docs/ISSUES.md`, and any other docs you edit) **between chunks of work** so you always have fresh context. Do not rely on stale recall.
   - **Before moving to the execution plan** (and before each major step), **check every decision** to see if it could be a hallucination: Am I assuming something not stated in the docs? Am I inventing endpoints, behavior, or requirements? If in doubt, re-read the relevant file and only then proceed.

## Execution plan (do in order)

### A) Baseline audit

- Read:
  - `docs/AGENT_WEAK_PLACES.md` (**first** — OPEN rows are your queue)
  - `docs/GOALS.md`
  - `docs/ISSUES.md`
  - `docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md` (once, for context)
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
- Run issue-resolution live tests. For **per-test timing** (find slow cases), run **`scripts/run_live_e2e_tests_one_by_one.py`** and read **`docs/live_e2e_test_timings.md`** — see **`docs/PERFORMANCE_TESTING.md`**.
- If failures occur, fix immediately and rerun until green.

### E) Real E2E: run the tool and improve in a loop (mandatory — do not skip)

You must run the tool for real and communicate with it. Do not stop and propose the user run E2E; you run it. **Before starting E2E:** Reread `docs/GOALS.md` and `docs/ISSUES.md` for fresh context; check that your planned test data and expected risks are grounded (no hallucinated assumptions).

1. **Ensure the stack is running.** Start Docker (e.g. `cd docker && docker compose up -d`) if the API is not reachable. Wait for health (e.g. `curl http://localhost:8000/health`). If startup fails, fix and retry.

2. **Generate brand-new E2E test data for every loop iteration (mandatory).**

   - **Every** time you run section E in a loop, you must **create new documentation** for that iteration. **Do not** reuse the same fixture file or the same doc text as the previous loop’s primary E2E (e.g. do not run E2E only on `doc_onetime_loan_portal.md` every time). Each loop: a **new fake project/API** (new paths, new resource names, new scenario).
   - **Before writing:** List 3–5+ **inserted high-risk BOLA possibilities** for **this** doc. **Write “expected risks” for this run only** — they define what the system must surface for **this** data.
   - **Then write** the doc so those risks are present; vary REST / GraphQL / SOQL / legacy / cross-tenant as appropriate.
   - **Diversity is mandatory across loops:** do not keep running Salesforce-only or HAR-only docs; rotate systems and document types.
   - Save as a **new** file (e.g. `tests/fixtures/doc_onetime_<shortname>_<loop>.md` or a dated name) or one-time payload; tag which loop it belongs to in your notes.

3. **Communicate with the tool via the API as a person would — new questions every loop.**

   - Use **separate** API calls (e.g. individual `curl` or equivalent), **not** one opaque script that hides each step.
   - **Document intake path for this project:** place the generated doc into the shared Docker docs path (`shared_docs` on host, mounted as `/shared-docs` in container), then ingest via **`POST /ingest_shared`** (or `bola-ai ingest-shared`) using a relative filename. Prefer this over pasting raw content for full-cycle E2E.
   - **Every loop**, compose **new natural-language questions** tied to **this run's generated doc** (how a security reviewer or auditor might ask — different wording each time). **Do not** recycle the same canned queries every iteration.
   - Minimum flow: **POST /reset** → **POST /ingest_shared** (this loop's new doc) → **POST /analyze** (first person-style question) → additional **POST /analyze** calls driven by step 3a below.
   - **After every single response, stop and analyze the response manually before formulating the next question** (see step 3a). The next question must be derived from what the model actually returned — never from a pre-planned script.

3a. **Mandatory per-response analysis and adaptive questioning (non-negotiable).**

   After **every** `POST /analyze` call, before sending the next request, perform a full per-response review and make a documented decision about what to ask next. **Do NOT queue up a fixed list of questions in advance. Do NOT skip straight to the next question without reading and evaluating the one you just received.**

   **Per-response checklist (run for every response, no exceptions):**

   | # | Check | Action if fails |
   |---|-------|-----------------|
   | R1 | **Endpoint coverage** — list which expected endpoints appear in the response and which are missing | Ask a follow-up targeting each missing endpoint by name before advancing |
   | R2 | **Rationale accuracy** — does the rationale describe an ownership/object-level gap? Does it confuse domain terms (e.g. "property" for an account endpoint)? Does it conflate authentication ("valid token required") with BOLA ("owner not verified")? | Ask the model to clarify; file normalization WP if systemic |
   | R3 | **Verification step validity** — do steps use two different **valid** user tokens on the same object ID? Or do they say "call with an invalid token" / "call without a token"? | Note; check if normalization handles it; if not, file WP and fix before next question |
   | R4 | **Curl path accuracy** — if curl examples are present, does each finding's curl use the **correct path for that finding**? (e.g. `/properties/{propertyId}/billing` for the billing finding, not a different documented path) | Note as WP-010-class error; document in per-response log; if systemic, add WP |
   | R5 | **No spurious content** — does the response contain any of: cheat-sheet text, "Fix steps" sections (bold or plain), Python/Django code blocks, raw "## Notes" fixture sections (numbered or unnumbered), grounding suffix echo, hallucinated query params (`?owner=`, `?admin=`, `?tenant=`)? | File WP and fix normalization immediately; re-run the same question after fixing |
   | R6 | **Grounding** — do all cited paths appear verbatim (or as the same `{param}` pattern) in the ingested doc? Any invented path or resource not in the fixture is a hallucination | File OPEN issue; check normalization path redaction |
   | R7 | **Auditor usefulness** — would a real SOC analyst act on this response? Are steps concrete, copy-pasteable, and unambiguous? | Decide whether to ask for more detail as the next question |

   **Adaptive next-question decision (mandatory after each response):**

   Based on the checklist above, choose exactly one action:
   - **(a) FOLLOW-UP on a miss (R1 failed):** Ask explicitly about each missing endpoint by name. Example: "What is the BOLA risk for PATCH /accounts/{accountId}/contact specifically?"
   - **(b) FIX THEN RE-ASK (R5 failed):** Stop. Fix the normalization, run tests, sync to container, then re-ask the same question to confirm the fix is live before advancing.
   - **(c) CLARIFY QUALITY ISSUE (R2, R3, or R4 failed):** Ask a targeted follow-up to probe the problematic output. Example: "You mentioned 'property' in the rationale — do you mean account? What ownership check is missing for PATCH /accounts/{accountId}/contact?"
   - **(d) PROBE DEEPER (R7 borderline):** Ask for more detail. Example: "Explain step by step how an attacker would exploit the GET /districts/{districtId}/accounts finding. What exact account data would they see?"
   - **(e) ADVANCE to next question type (only if R1–R7 all pass):** Move to curl generation, runbook, fake-data tokens, or self-audit question as appropriate.

   **Log every decision inline.** Before each `POST /analyze` request, write: `Analysis of previous response: [brief per-R1..R7 assessment] → Decision: [a/b/c/d/e] because [reason]`. This makes the session a real adaptive conversation, not a script replay.

4. **Expectations are derived only from this loop’s generated data.**

   - For **this** doc, your **expected risks list** (step 2) is the **sole expectation checklist** for strict coverage. **Do not** judge the output against a prior loop’s expectations.
   - Compare tool output to **this run’s** inserted risks, paths, and person-style questions.

5. **Wider E2E communication (act as user, follow-up, fake data, validation) — mandatory every loop:** After the initial response(s), **pretend you are the end user** and run a **wider set of communication** with the tool. **Do not** end section E with only three initial questions; **`scripts/run_agent_e2e_loop_once.py`** implements the minimum (**6** separate `POST /analyze`: 3 initial + runbook/200–403 + fake-token curls + path self-audit). Do all of the following and record outcomes:
   - **Ask for more details:** Send one or more additional POST /analyze requests asking the tool for more detail (e.g. “For the first finding, give more detailed step-by-step verification steps”, “Explain how to interpret the result if user B gets 200 vs 403”).
   - **Ask for more detailed steps:** Request concrete, copy-pasteable steps (e.g. “List the exact order of API calls for a two-token BOLA test”).
   - **Provide fake data and ask for request/query generation:** In a follow-up query, supply **fake but realistic** data (e.g. “Assume I have Bearer token for user A (userId=u-123) and user B (userId=u-456), and a loan ID loan-789 that belongs to user A. Generate the exact HTTP requests or curl commands to test BOLA for GET /api/v2/loans/{loanId}”). Capture the tool’s suggested requests/queries.
   - **Validate the tool’s suggested requests and queries:** Check that the generated requests (a) use the **exact endpoints from the ingested doc**, (b) include two distinct tokens/users and the same object ID where relevant, (c) do not contain hallucinated parameters or paths. Note any errors or hallucinations.
   - **Analyze and act:** After this wider communication, **analyze** whether the tool's follow-up answers are correct, grounded, and useful. If you find **bugs or quality problems**, create **OPEN** issues in **`docs/ISSUES.md`** (with description, acceptance, autotest name). If you identify **improvements** (prompts, normalization, RAG, training), implement them immediately or register as **OPEN** weak-place rows and fix in the same session. **Do not** write E2E run logs, activity summaries, or "Last E2E cycle" entries into ISSUES.md — **ISSUES.md is strictly for actionable issues** (bugs, regressions, missing capabilities) with acceptance criteria and autotests. E2E run notes belong in your chat output, not in the issue tracker.
   - **Failing steps: analyze and fix, do not work around.** If any request **times out, fails, or returns a result that is not acceptable** (e.g. wrong content, cuts, or poor quality), **do not** try to make the step “pass” by lowering the bar (e.g. increasing client timeout, shortening the query, or cutting scope). Instead: **analyze the root cause**, then **file an E2E-loop-failure issue** (see **E2E-loop failure issues** below)—not mixed with generic product bugs unless the same fix applies. **Fix the underlying cause** in the next loop. No quality shortcuts.

6. **Verify the LLM fully and strictly covers all inserted high-risk possibilities (no partial credit):**
   - **Strict condition:** For the run to pass, **every** high-risk possibility you inserted (step 2) must be **explicitly** present in the report with: (a) the **exact endpoint or operation** from the test doc (e.g. `GET /api/v2/loans/{loanId}`, `GET /api/v2/orgs/{orgId}/settings`, `POST /api/v2/loans/batch`), (b) a clear BOLA risk statement for that endpoint, and (c) verification steps that use **two valid user tokens** on the same object ID (not 401/404 alone). Partial coverage (e.g. only 1 of 5 risks, or correct path but wrong verification) **fails** the condition.
   - **Checklist:** Go through your expected-risks list one by one; for each, confirm the report contains a finding that names that endpoint/operation and has valid two-token verification. If **any** inserted risk is missing or only vaguely/partially covered, treat as a failure: document what was missed, then improve training/RAG/prompts and **repeat the main prompt** (full cycle) before the next E2E run.
   - The report must also stay grounded (no hallucinated endpoints/resources). Any invented path or finding not in the test doc is a failure.

7. **Analyze whether the tool’s responses are correct and helpful (especially follow-ups q4–q6):**
   - Does the report identify real BOLA risks implied by the test doc?
   - **Grounding gate:** In **runbook** and **path-audit** answers, **every** cited path, GraphQL operation, or SOQL snippet must appear in the **source doc**. If the model invents `document(id)`, random SOQL, or paths not in the doc → **not acceptable**; document in **`docs/ANALYSIS_E2E_GROUNDING_GAP.md`** style, fix **`prompts.py`** / RAG, re-run E2E before claiming “no improvements.”
   - Is verification logic valid (two valid user tokens, not 401/404 alone)?
   - Would an auditor be able to act on the suggestions?
   - Note any missing findings, wrong logic, or weak wording.

8. **Find what is missing and can be improved:**
   - Missing BOLA patterns, wrong verification phrasing, off-topic findings, malformed output.
   - Consider whether the learning curve (training data in `generate_data.py`, RAG chunks, system prompt in `prompts.py` or Modelfile) should be updated to fix or prevent these.

9. **Manual web verification (mandatory every loop):**
   - Open `http://localhost:8000/chat` in a browser (or use browser automation).
   - Verify the chat UI loads: header with "BOLA AI", green health dot, welcome message.
   - Send `help` — verify the usage guide renders with all sections.
   - Send `list files` — verify shared docs listing.
   - Send `ingest <filename>` (from the listing) — verify success message.
   - Send a BOLA question — verify analysis response with markdown.
   - Send `status` — verify system info.
   - **All 7 checks must pass.** If any fail, file an OPEN issue.
   - See `docs/E2E_TESTING.md` for full checklist.

10. **Iterate:** If you found problems or improvements (including strict-coverage failure in step 6 or issues from step 5):
   - **Implement and document** any learning improvements from step 5 or step 6 **before** the next loop—e.g. update `generate_data.py`, RAG, prompts, or normalization; regenerate training and reload RAG.
   - **E2E-loop failures** (strict coverage miss, timeout on this loop’s doc, bad follow-up, hallucinated curls): use **E2E-loop failure issues** (see below); add a **dedicated autotest** in `tests/test_e2e_loop_failures.py` (not in `test_issues_resolved.py`). Run that test file **separately** when verifying the fix; regular CI / issue-resolution runs use `test_issues_resolved.py` and generic E2E.
   - Other bugs: log in `docs/ISSUES.md` as today; `test_issues_resolved.py` where applicable.
   - If strict coverage failed: improve training/RAG/prompts, then **repeat the full cycle** with **another brand-new doc** (step 2).
   - Run unit tests, then run real E2E again (including step 5) with **new** one-time docs.
   - Repeat until strict coverage and follow-up steps are satisfactory.

**E2E-loop failure issues (separate from regular issues):**

- When an **agent E2E loop** fails (e.g. missed inserted risk, analyze timeout for **this loop’s** doc, poor person-style follow-up), open an issue with prefix **`[E2E-LOOP]`** in the title.
- Include: **link or path to this loop’s generated doc**, the **expected risks list** for that doc, **actual failure** (what the tool did vs expected), **acceptance** (how we know fixed).
- **Autotest:** Add or extend **`tests/test_e2e_loop_failures.py`** — one test per `[E2E-LOOP]` issue, reproducing that scenario (same doc fixture or minimal excerpt + analyze assertions). **Do not** put these in `tests/test_issues_resolved.py`. Mark the issue PASSED only after that dedicated test passes on live API (or document skip if env unavailable).
- Regular E2E (`test_e2e_llm.py`, manual scripts) and **issue-resolution tests** stay independent; `[E2E-LOOP]` items are **tracked and retested on their own**.

**Validation criteria for each response (use as checklist in step 3a):**

1. **Grounding:** All cited paths, GraphQL operations, and SOQL snippets appear verbatim (or as `{param}` pattern) in the ingested doc. No invented endpoints.
2. **No hallucinated endpoints:** Report does not assert findings for paths not in the provided documentation.
3. **BOLA-focused:** Findings describe object-level authorization gaps (ownership, cross-tenant, linked resource access) — not generic authentication presence or filtering/pagination issues.
4. **Verification logic valid:** Steps use two different **valid** user tokens on the same object ID. Not "call without a token", not "call with an invalid token", not "if 401 BOLA confirmed".
5. **Readable, consistent output:** No malformed headings (e.g. `### ### Title`), no duplicate verification steps, no truncated findings (heading only, no body).
6. **Actionable for an auditor:** Steps are concrete and copy-pasteable. An auditor can execute them without guessing.
7. **GraphQL (if doc contains it):** Findings reference named operations/fields from the doc; verification uses GraphQL syntax and two valid tokens.
8. **SOQL/Salesforce (if doc contains it):** Findings reference record-level risks (WITH SECURITY_ENFORCED, sharing model, cross-object subqueries).
9. **No spurious output blocks:** None of the following appear: "BOLA Remediation Cheat Sheet" from knowledge base; "Fix steps" sections (bold `**Fix steps:**` or plain `- Fix steps:`); Python/Django/Express implementation code blocks (`def`, `class`, `.objects.`); raw `## Notes` / `### N. Notes` fixture sections; `GROUNDING_USER_SUFFIX` echo ("Mandatory grounding (person-style…)"); hallucinated query params (`?owner=`, `?admin=`, `?tenant=`, `?uuid=`).
10. **Curl path accuracy:** Each finding's curl example uses the **correct path for that finding** — not a path from a different finding in the same response. (Known 1.5B model limit — WP-010/Issue 22 — note occurrences per response.)
11. **Rationale domain accuracy:** Rationale uses correct resource terminology matching the endpoint (e.g. "account" for `/accounts/` endpoints, "property" for `/properties/` endpoints — not mixed).


### F) Issue logging and fixes

- Any failed criterion, defect, **or interrupted/incomplete cycle** ⇒ create/update **OPEN** issue in `docs/ISSUES.md`. OPEN issues are the **queue** for the next loop — finishing a session with OPEN items is expected; the **next** session continues until they are PASSED or legitimately closed.
- **Agent E2E loop failures** ⇒ `[E2E-LOOP]` issues + `tests/test_e2e_loop_failures.py` (see section E).
- Other defects: implement fix; add autotest in `test_issues_resolved.py` where that file tracks the issue.
- Mark issue PASSED only after the **correct** test track passes and real E2E check succeeds where required.
- **ISSUES.md is for actionable issues only** — not E2E activity logs or run summaries. Each entry must have: description, acceptance criteria, autotest name, and status. Do not add "Last E2E cycle" log entries or run timelines to ISSUES.md.
- Then repeat the improvement loop (E).

### F2) Improvement thinking (mandatory at end of every loop)

After E2E and issue fixes, **before** checking stop conditions, **deliberately think about possible tool improvements:**

1. **Reflect on what you observed:** Review all tool responses from this cycle. What could the tool do better? Think about: output quality, grounding accuracy, verification logic, prompt effectiveness, normalization gaps, RAG relevance, UI/API ergonomics, test coverage, documentation clarity, deployment robustness.
2. **List concrete improvement ideas:** Write them down explicitly (in your chat output). Do not skip this step even if everything "looked fine" — there is always something to improve in a world-class tool.
3. **For each idea, decide and act:**
   - If the improvement is **actionable now** (code change, prompt tweak, new test): **implement it immediately**, then re-run relevant tests.
   - If it is a **new success criterion** or quality bar: add it to **`docs/GOALS.md`**.
   - If it is a **bug or regression**: add it as an **OPEN** issue in **`docs/ISSUES.md`** with acceptance criteria and autotest name.
   - If it requires **investigation or larger work**: add an **OPEN** row to **`docs/AGENT_WEAK_PLACES.md`** and start a fix loop.
4. **If you added any OPEN items** from this thinking step, **you must start a new loop** to address them before checking stop conditions. You are not done until those items are closed.

### G) Pre-finish mandatory check + stop condition

**Before** evaluating stop conditions, **you must perform this mandatory check:**

1. **Reread `docs/AGENT_WEAK_PLACES.md`** — are there any **OPEN** rows?
2. **Reread `docs/ISSUES.md`** — are there any **OPEN** issues?
3. **Reread `docs/GOALS.md`** — are there any unresolved goals you own?
4. **If ANY of the above exist:** You **must not stop**. **Start a new loop immediately** — go back to the relevant section (fix the issue, close the weak place, address the goal) and continue until the item is resolved. **Do not** report completion while open items exist.
5. **Only after confirming ALL are clear** may you proceed to the stop condition check below.

**Stop condition (only when there is NO job for the next loop)**

**Stopping is forbidden** if **any** next-loop job exists (see opening “Continuous loop” and **AGENT_WEAK_PLACES**). **You may stop only when all** are true:

- **No OPEN rows** in `docs/AGENT_WEAK_PLACES.md` (registry clear or all VERIFIED for this cycle).
- **No OPEN issues** in `docs/ISSUES.md`.
- **No unresolved goals** in `docs/GOALS.md` (for items you own).
- **No improvement proposals remaining:** After deliberately listing **every** idea you would otherwise put in a “future work” or “could improve” paragraph: **each** must be either **already shipped** in this cycle **or** reflected as an **OPEN** row you then **closed** in a **follow-up loop in the same session**. If you would still suggest something to a colleague, **you are not done**.
- **Self-audit table (mandatory before final message):** Output a markdown table: | Claim | Evidence (file/test/log) | Still weak? | — for: registry empty, ISSUES clean, E2E done, tests green. **Every “Still weak?” must be NO** or you continue looping.
- **This cycle’s section E is complete:** for **this** iteration you generated **new** test data, ran reset → ingest → analyze with **new** person-style questions, ran step 5 (wider communication), and recorded **strict coverage** vs **this doc’s** expected-risk list (pass, or **[E2E-LOOP]** issue + fix plan + **immediate** fix loop until pass or documented stack blocker).
- **`pytest tests/` passes** with the **full live stack** (E2E is mandatory when those tests are collected — see docs/E2E_TESTING.md); or OPEN issue if stack truly unavailable with owner.

If **anything** above is unfinished—including **not yet running E2E for this cycle**—either **do not stop** and finish, **or** file an **OPEN** issue **and** **OPEN weak-place row** capturing the remainder; **then continue** in the same session if context allows. Only if **impossible** (e.g. user aborted, stack down) may you stop after filing; **never** stop with “good enough” while OPEN registry rows exist. A loop that **ends with OPEN issues or OPEN weak places** is **not** “completion satisfied” — it is **incomplete work** unless the user explicitly stopped the session.

## Operational constraints

- Do not use destructive git commands.
- Do not revert unrelated user changes.
- Keep logs concise but sufficient.
- Track memory regularly and avoid high-risk commands if memory spikes.
- If Docker/model operations fail, fix and continue autonomously.
- **Timeouts (Issue 17):** You **may** increase **`BOLA_AI_INGEST_TIMEOUT`**, **`BOLA_AI_STACK_WAIT_SECONDS`**, Docker healthcheck **start_period**, and **`health --wait`** for ingest/training/startup. You **must not** raise **`BOLA_AI_LLM_CHAT_TIMEOUT`** or **`BOLA_AI_ANALYZE_CLIENT_TIMEOUT`** to make slow LLM answers “pass”—fix inference quality or capacity instead.

### H) Fresh-image hands-free E2E (mandatory when startup/ingest/analysis changes)

When the current cycle includes changes to startup behavior, auto-ingest, auto-analysis, Ollama context, or the all-in-one image:

1. **Push changes** and wait for the GitHub Actions image build to complete (~10 minutes).
2. **Remove all BOLA containers and images** locally:
   ```
   docker rm -f $(docker ps -aq --filter "ancestor=ghcr.io/igorredkach/bolai:latest") 2>/dev/null
   docker rmi ghcr.io/igorredkach/bolai:latest 2>/dev/null
   ```
3. **Delete all files** from `~/Downloads/shared` (or the host shared folder) and **generate brand-new test data** there (new API doc with unique endpoints and inserted BOLA risks).
4. **Run the image from scratch:**
   ```
   docker run -p 8000:8000 -v ~/Downloads/shared:/shared-docs ghcr.io/igorredkach/bolai:latest
   ```
5. **Wait 15 minutes** (model load + auto-ingest + auto-analysis).
6. **Open `http://localhost:8000/chat`** — the auto-analysis result should already be displayed without the user typing anything. Verify:
   - Analysis is present and grounded (only endpoints from your generated test data)
   - No hallucinated endpoints
   - Health dot is green, status shows doc count
   - Chat history persists across reload
7. **Talk to the agent** — send follow-up questions via the chat UI. Verify responses are ONLY related to the test data you generated (no generic training data leaking).
8. **If all good:** Section H passes. If issues found: create OPEN issues/weak-places and immediately start a new loop.

## Output format I want from you at the end

1. What gaps were found vs goals.
2. What refactors were done and why.
3. Training data / learning-curve changes (before/after counts + quality improvements).
4. Retraining/adaptation steps executed.
5. New issues added and how each was fixed.
6. Tests run with results (unit + real E2E).
7. Real E2E: **new test data** with **inserted high-risk possibilities**; **expected high-risk list**; all requests (initial + follow-up with fake data); tool responses; **strict coverage** result (each inserted risk explicitly present with exact endpoint and two-token verification?); **wider communication** outcomes (more details, generated requests/queries, validation result); and any **documented learning improvements or tool changes** applied before the next loop.
8. Final statement: either (a) **no job remained** — **AGENT_WEAK_PLACES** has no OPEN rows, no OPEN issues, section E done, tests green, **self-audit table all NO on “Still weak?”** — or (b) user/environment **forced** stop after you filed **OPEN** issue(s) **and** **OPEN weak-place row(s)**.
9. List any **OPEN** issues **and OPEN weak-place IDs** left (if any). If none, state **registry clear** date.
