# E2E Testing (always live)

Runs after pytests and any manual test scripts when you are doing full quality sign-off.

**Agent quality loop:** Full-cycle agents follow **`docs/AGENT_PROMPT_FULL_CYCLE.md`**, track weak spots in **`docs/AGENT_WEAK_PLACES.md`**, and continue until registry + ISSUES are clear (see **`docs/ANALYSIS_AGENT_LOOP_STOP_GAP.md`**).

**E2E is always live:** Tests that hit the real API + LLM **do not silently skip** — **`pytest tests/` fails at collection** if the API + Ollama are not reachable at `BOLA_AI_LIVE_URL` (default `http://localhost:8000`). If something fails, file or update an **OPEN** issue, fix it, and re-run the loop.

Quality is validated on the **real** stack, not optional mocks.

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

If you cannot run live tests, create an **OPEN** issue, stop the current “done” narrative, fix the blocker, and start a new improvement loop.

Live E2E is not skipped by default; if the environment truly cannot run them, document that in open  ISSUES and start a new improvement loop.

---

## What we assert (live LLM) — goals for any E2E pass

1. **Fresh documentation every meaningful E2E cycle**  
   Generate new test documentation from scratch for that run: think through the **system under test**, **plausible BOLA angles**, and **what you expect** the tool to surface before you write the doc.  
   **Required intake path:** copy the doc into the shared Docker docs path (`shared_docs` on host, mounted to `/shared-docs` in container), then ingest via **`POST /ingest_shared`** (or CLI `bola-ai ingest-shared`) after **`POST /reset`**.

2. **Reports match tool goals**  
   Responses should stay **BOLA-focused**, include **actionable verification steps**, and stay **grounded** in the ingested doc (paths, methods, no invented GraphQL/SOQL when the doc is REST-only, etc. — see **`docs/GOALS.md`**).

3. **Primary method: adaptive person-style E2E (not “the script = the test”)**  
   think about possible question a person can ask for more details and support according to the generated context. Evaluate after each tool response. And verify responses according to the expectations you believe are correct for the context

   **How adaptive E2E should work:**

   | Step | What you do |
   |------|----------------|
   | **Start the stack** | Docker up, health OK. |
   | **Pass generated data** | Reset → copy doc to `shared_docs/` → ingest with **`POST /ingest_shared`** using relative filename. |
   | **First request** | One **`POST /analyze`** with a natural question tied to that doc (e.g. auditor angle on ID abuse). |
   | **Read the answer** | Judge it against **your scenario**: coverage, grounding, verification logic (e.g. two valid tokens vs 401/404-only). |
   | **Next request from context** | Ask a **new** question **informed by what the model just said** (deeper steps, challenge a finding, ask for curls with fake tokens, ask for a runbook, ask it to audit its own paths). **Separate request each time** — do not hide a long chain inside one opaque script unless you are only using the script as a smoke baseline. |
   | **Repeat** | Continue **analyse response → decide next question → send next `POST /analyze`** until you are satisfied the tool has been **exercised enough** for this doc (several turns, not a fixed number — often **more** than six if answers were shallow or drifted). |
   | **Per-response analysis** | For **every** tool response, briefly note: grounded? BOLA-relevant? verification sound? regressions vs earlier answers in the same session? |

   **When to stop (“tested enough” for this cycle):** You have probed **follow-ups**, **edge of doc** (e.g. batch endpoints), and **hallucination risk** (paths in answer vs ingested text); you are not stopping only because the first reply “looked fine.”

4. **Improvements become work items**  
   Anything that should change product or process or possible improvements you see  → **`docs/ISSUES.md`** (bugs, `[E2E-LOOP]` if script-level regression) and/or **`docs/GOALS.md`** (new or tightened success criteria).

---

## NO Scripted minimum (smoke should be created but not as a substitude for the e2e test described before)

`scripts/run_agent_e2e_loop_once.py` enforces **6** separate **`POST /analyze`** calls (3 persona questions + runbook/200–403 + fake-token curls + path self-audit) for a chosen fixture. Use it to **regress** grounding and follow-up shape; **still** run adaptive person-style passes when you care about depth.

By default the script now stages the selected fixture into `shared_docs/` and ingests via **`POST /ingest_shared`** (set `BOLA_AI_E2E_USE_SHARED_VOLUME=0` only for debugging legacy behavior).

Log output: **`docs/e2e_loop_last_run.json`**.
Release sign-off = full **`pytest tests/`** with stack up.

**Agents:** If live E2E cannot complete, or **OPEN** issues / unresolved goals remain, start new loop according **`AGENT_PROMPT_FULL_CYCLE.md`** §3b.

---

## Manual web verification (mandatory in every E2E cycle)

After API-level E2E completes, verify the **interactive web chat** works:

1. **Open `http://localhost:8000/chat`** in a browser (or use browser automation).
2. **Verify page loads:** Header shows "BOLA AI" with a green status dot. Welcome message is visible.
3. **Test "help" command:** Type `help` and send. Verify the usage guide appears with sections: Getting Started, Commands, Example Conversation, Tips.
4. **Test "list files" command:** Type `list files` and send. Verify the shared docs listing appears.
5. **Test "ingest" command:** Type `ingest <filename>` (using a file from the listing). Verify the success message shows character count and chunk count.
6. **Test analysis question:** Type a BOLA-related question. Verify the response appears (may take 1-4 minutes) with markdown formatting (headings, bold, code blocks).
7. **Test "status" command:** Type `status`. Verify system info appears (Ollama status, chunk count).

**Pass criteria:** All 7 steps succeed. The chat UI renders markdown correctly, auto-scrolls, and the loading spinner appears during analysis.

If any step fails, file an **OPEN** issue in `docs/ISSUES.md` and fix before claiming E2E completion.
