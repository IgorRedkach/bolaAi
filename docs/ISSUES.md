# Open issues and improvement tracker

**Agent policy:** If a quality run **fails** or the **loop is interrupted**, add or keep an **OPEN** issue describing what failed or what was left undone. The **next** agent loop must work **OPEN** issues, goals, and improvements until cleared. You **may** write progress summaries anytime, but you **must not stop** the improvement work until **no OPEN issues**, **no unresolved goals**, and **no further improvements** you can name (see `AGENT_PROMPT_FULL_CYCLE.md`).

When an issue is fixed, mark it **PASSED** and add an autotest that would have failed before the fix.

- **Regular / product issues:** Autotests in `tests/test_issues_resolved.py`.
- **Agent E2E loop failures** (strict coverage miss, loop doc timeout, bad follow-up on **that loop’s** data): Title prefix **`[E2E-LOOP]`**. Autotests in **`tests/test_e2e_loop_failures.py`** only — **not** mixed into `test_issues_resolved.py`. Run that file **separately** when fixing/verifying those issues.

**Run issue-resolution tests (live E2E, mandatory when collected):**
```bash
# Stack must be up (default http://localhost:8000)
PYTHONPATH=src pytest tests/test_issues_resolved.py -v -s
```

**Run E2E-loop failure regressions (live, when tests exist):**
```bash
PYTHONPATH=src pytest tests/test_e2e_loop_failures.py -v -s
```

Requires the stack running with Ollama and `bola-analyzer` model.

**Prompt and RAG:** Prompt was updated to reduce hallucination and off-topic findings (see `src/bola_ai/agent/prompts.py`). If issues persist, consider adding BOLA-only examples to RAG or retraining.

---

## Issue 1: Hallucinated endpoints in report

**Status:** PASSED

**Description:** The LLM sometimes mentions endpoints that are not in the ingested documentation (e.g. `/api/users/{id}` when the doc only has `/api/v1/patients/`, `/api/v1/orders/`, `/api/v1/prescriptions/`, `/api/internal/cases`).

**Acceptance:** Report must not assert BOLA findings for endpoints that do not appear in the provided documentation.

**Autotest when passed:** `tests/test_issues_resolved.py::test_report_does_not_reference_unknown_endpoints`

---

## Issue 2: Off-topic findings (pagination, filters) labeled as BOLA

**Status:** PASSED

**Description:** The LLM sometimes reports "BOLA" for non-BOLA concerns (e.g. pagination, order status/type/date filters). BOLA is specifically about **object-level authorization** (can user A access object X that belongs to user B?), not about filtering or pagination.

**Acceptance:** Findings should be limited to object-level authorization (ownership, cross-tenant, linked resource access). Pagination/filtering may be noted separately or not as BOLA.

**Autotest when passed:** `tests/test_issues_resolved.py::test_report_bola_findings_are_authorization_related`

---

## Issue 3: Conflating authentication with ownership

**Status:** PASSED

**Description:** Rationale sometimes says "does not state that users must be authenticated" when the doc clearly says "Requires valid token". The gap we care about is **ownership** (is this user allowed to access *this* patient/order?), not authentication.

**Acceptance:** Rationales should focus on missing **ownership/permission** checks for the object ID, not on whether authentication is required.

**Autotest when passed:** `tests/test_issues_resolved.py::test_report_rationale_focuses_on_ownership_not_auth`

---

## Issue 4: Duplicate or malformed headings in output

**Status:** PASSED

**Description:** Output sometimes has "### ### Title" (double heading) or inconsistent markdown structure.

**Acceptance:** Each finding uses a single "###" (or "### Title") and consistent structure: Title, Rationale, Verification steps.

**Autotest when passed:** `tests/test_issues_resolved.py::test_report_has_consistent_finding_structure`

---

## Issue 5: Verification steps must use "two different user tokens" for IDOR

**Status:** PASSED

**Description:** Correct BOLA verification for "can user A access user B's resource?" is: call the same endpoint with **two different user tokens** and compare; if both get data, object-level check may be missing. Some reports say "call with valid token" and "if returns data BOLA confirmed" without the two-token comparison.

**Acceptance:** At least one verification step per finding should explicitly mention two tokens or two users (e.g. "with two different user tokens", "as two different users").

**Autotest when passed:** `tests/test_issues_resolved.py::test_verification_steps_mention_two_tokens_or_two_users`

---

## Issue 6: Verification steps must not suggest testing "without a token"

**Status:** PASSED

**Description:** BOLA verification must use two different *authenticated* user tokens to compare access. Some reports suggest calling an endpoint "without a token" or "unauthenticated"; that tests auth presence, not object-level authorization.

**Acceptance:** Verification steps must not suggest testing without a token. They should require two different user tokens (or we post-correct and append the reminder).

**Autotest when passed:** `tests/test_issues_resolved.py::test_verification_not_without_token`

---

## Issue 7: Infinite loop in chunking causes OOM

**Status:** PASSED

**Description:** `_split_sentences` in `src/bola_ai/rag/chunking.py` had an infinite loop when the last chunk was shorter than `overlap`. The final slice (`start=590, end=600` for a 600-char string with `overlap=10`) would set `new_start = end - overlap = 590`, never advancing. This caused unbounded chunk generation and OOM (20+ GB).

**Acceptance:** `chunk_text("A. " * 200, chunk_size=100, overlap=10)` must complete in <1s and produce a finite, reasonable number of chunks (< 20). Tests must run under 10 GB memory limit.

**Autotest:** `tests/test_rag.py::test_chunk_text_large` (previously crashed, now passes). Memory limit enforced in `tests/conftest.py` via `resource.setrlimit`.

---

## Issue 8: Bold-wrapped heading markers (**### Title**)

**Status:** PASSED

**Description:** LLM sometimes outputs `**### Rationale**` or `**### Verification Steps**` instead of `**Rationale:**` or `### Rationale`. The bold markers wrap the `###` heading syntax, creating malformed markdown.

**Acceptance:** Report must not contain `**###` pattern. Headings should be clean `###` or bold `**` but not both wrapping each other.

**Autotest:** `tests/test_issues_resolved.py::test_no_bold_wrapped_headings`

---

## Issue 9: Invalid BOLA confirmation logic on 404 results

**Status:** PASSED

**Description:** Some responses used incorrect logic such as "if both requests return 404, BOLA is confirmed." A 404 can mean the object does not exist and does not confirm object-level authorization failure.

**Acceptance:** Reports must not claim BOLA confirmation from `404` outcomes alone. Guidance should instruct using an existing object ID (owned by user A) and comparing access with user B.

**Autotest:** `tests/test_agent.py::test_normalize_report_rewrites_invalid_404_bola_confirmation`

---

## Issue 10: Endpoint drift to unrelated APIs in generated suggestions

**Status:** PASSED

**Description:** In some manual runs (e.g., banking documentation), the model suggested unrelated endpoints such as `/api/v1/patients/...`, despite the ingested doc containing only `/banking/v1/...` endpoints. This reduced auditor trust and actionability.

**Acceptance:** Suggested endpoint paths in the report must be grounded to ingested context. Unknown paths should be redacted and replaced with guidance to use documented endpoints only.

**Autotest:** `tests/test_agent.py::test_normalize_report_redacts_paths_not_in_allowed_context`

---

## Issue 11: Incorrectly treating authentication failures as BOLA confirmation

**Status:** PASSED

**Description:** Some outputs treated authentication outcomes (`401 Unauthorized`, invalid token) as evidence that BOLA is confirmed. This is incorrect: auth failures only show authentication behavior, while BOLA requires object-level authorization comparison using two valid users/tokens.

**Acceptance:** Reports must not claim BOLA confirmation from `401` or invalid-token outcomes. Guidance should require two valid user tokens against the same existing object ID.

**Autotest:** `tests/test_agent.py::test_normalize_report_rewrites_invalid_401_bola_confirmation`

---

## Issue 12: GraphQL operations not recognized as BOLA surfaces

**Status:** PASSED

**Description:** GraphQL uses a single endpoint (e.g. POST /graphql). BOLA occurs in query/mutation **operations** and **field arguments** (e.g. `user(id: "123")`, `deleteDocument(id: ID!)`), not in URL paths. The tool may miss GraphQL BOLA or treat it as REST-only. Path extraction regex targets `/api/...` and does not extract GraphQL operation names, field names, or argument patterns. A related normalization gap: heading bleed `**Title**# **Rationale:**` was produced by the LLM for GraphQL docs. Verification steps incorrectly tested auth ("use a token without required permissions") rather than BOLA (two valid user tokens).

**Acceptance:** When documentation describes GraphQL (queries, mutations, subscriptions), reports must: (1) identify BOLA risks in operations and arguments, (2) produce clean headings (no `**#` bleed), (3) verification steps must use two valid user tokens — not "token without permissions".

**Autotest when passed:** `tests/test_issues_resolved.py::TestIssuesResolved::test_report_identifies_graphql_bola` and `test_report_graphql_verification_uses_two_tokens`; unit tests in `tests/test_agent.py::test_normalize_report_fixes_graphql_heading_bleed`, `test_normalize_report_fixes_graphql_auth_only_verification`, `test_normalize_report_graphql_syntax_preserved`

---

## Issue 13: GraphQL nested resolvers and batch operations

**Status:** PASSED

**Description:** GraphQL BOLA can occur in nested resolvers (e.g. `User { orders { id } }` where orders resolver does not filter by user) or in batch/alias queries (`{ a: user(id: "1") {...} b: user(id: "2") {...} }`). Documentation may describe schema without stating resolver-level ownership checks.

**Acceptance:** Reports should flag nested fields that return object collections (e.g. orders, documents, cases) when docs do not state that resolvers enforce ownership. Verification should include testing nested selection with two different user tokens.

**Autotest when passed:** `tests/test_issues_resolved.py::TestIssuesResolved::test_report_graphql_verification_uses_two_tokens`

---

## Issue 14: SOQL and Salesforce record-level authorization

**Status:** PASSED

**Description:** SOQL (Salesforce Object Query Language) and Salesforce APIs have BOLA risks distinct from REST: sharing model (private, read, etc.), `WITH SECURITY_ENFORCED`, `UserRecordAccess`, cross-object queries, and profile/permission set vs record-level access. Docs may describe object permissions but not record-level checks.

**Acceptance:** When documentation describes SOQL, Salesforce objects, or Apex/API access, reports must identify record-level BOLA risks (e.g. SOQL without ownership filter, missing `WITH SECURITY_ENFORCED`, cross-object queries exposing related records). Verification steps should reference SOQL syntax and Salesforce sharing concepts where applicable.

**Autotest when passed:** `tests/test_issues_resolved.py::TestIssuesResolved::test_report_soql_identifies_record_level_bola`

---

## Issue 15: Report must not show Patient/Document/Order API when doc is claims-only (grounding)

**Status:** PASSED

**Description:** When ingested documentation describes only claims/policies (e.g. `/api/v2/claims/{claimId}`), the report must not list findings for "Patient API", "Document API", "Order API", or other resources not in the doc. Paths and finding titles must be grounded to the documentation.

**Acceptance:** Normalization redacts unknown paths and replaces hallucinated finding titles (Patient API, Document API, etc.) with "Endpoint from documentation" when those resources are not in the ingested doc. Unit test verifies this.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_grounds_claims_only_doc`

---

## Issue 16: /analyze timeout on complex queries (fake-data / request-generation step)

**Status:** PASSED

**Description:** The /analyze endpoint can exceed **120s** client timeouts because Ollama chat uses up to **300s** (`llm.chat`). Clients (CLI, curl, scripts) were timing out before the LLM finished.

**Acceptance:** Default HTTP client timeout for analyze is **≥ LLM chat timeout** (360s default via `BOLA_AI_ANALYZE_CLIENT_TIMEOUT` / `config.ANALYZE_CLIENT_TIMEOUT`). CLI `analyze` uses that value. E2E docs state minimum client timeout for `/analyze`. Example reports must not put Bearer tokens in query strings; use `Authorization` header (prompt + `_normalize_report`).

**Autotest when passed:** `tests/test_config.py::test_analyze_client_timeout_covers_llm_chat_timeout`, `tests/test_agent.py::test_normalize_report_fixes_bearer_token_in_query_string`

---

## Issue 17: Separate timeouts — learning/startup vs LLM inference reply

**Status:** PASSED

**Description:** Short timeouts on **ingest** (30s) and **health** caused failures during **embedding** and **Docker/Ollama startup**, while the team policy is: **do not** extend waits for the model **finishing a chat reply** as a workaround for slow inference. Time for the tool to **learn** from documents (ingest/chunk/embed) and for **stack/training start** must be configurable and generous; **LLM response** caps stay inference-sized.

**Acceptance:**

- **Inference:** `BOLA_AI_LLM_CHAT_TIMEOUT` (default **300s**) drives Ollama chat; **do not raise** to make slow generation “pass”—tune model/prompt/hardware instead. `BOLA_AI_ANALYZE_CLIENT_TIMEOUT` (default 360s) only needs to be ≥ LLM timeout so the HTTP client does not abort first.
- **Learning:** `BOLA_AI_INGEST_TIMEOUT` (default **600s**) for `POST /ingest` from CLI/scripts (embedding can be slow on CPU).
- **Startup / training:** `BOLA_AI_STACK_WAIT_SECONDS` (default **900s**) for `bola-ai health --wait`; `BOLA_AI_OLLAMA_STARTUP_PROBE_TIMEOUT` (default **60s**) for Ollama reachability checks; Docker Compose Ollama **healthcheck** `start_period` **600s**, longer **timeout** for cold `ollama list`.

**Autotest when passed:** `tests/test_config.py::test_ingest_timeout_allows_learning_not_inference`, `test_stack_startup_waits_separate_from_llm`

---

## Issue 18: E2E always live (no silent skip)

**Status:** PASSED

**Description:** E2E tests previously **skipped** when `BOLA_AI_LIVE_URL` was unset or the stack was down, so `pytest tests/` could look green without real LLM validation.

**Acceptance:** Collecting `test_e2e_llm.py`, `test_issues_resolved.py`, or `test_api_live.py` **fails at collection** if API + Ollama are not reachable (clear message). Full `pytest tests/` is the standard sign-off with stack up. **`BOLA_AI_SKIP_LIVE_E2E=1`** skips those tests only for emergency CI.

**Autotest when passed:** Manual: start stack → `pytest tests/` runs live E2E; without stack → collection exit 1; with `SKIP` → live tests skipped.

---

## Issue 19: Live E2E test timeout from accumulated ingested chunks

**Status:** PASSED

**Description:** `tests/test_e2e_llm.py` ingested fixture docs without resetting the store between tests. Over a full `pytest tests/` run this could accumulate chunks and make one analyze call hit timeout (`{"detail":"timed out"}`), creating flaky failures.

**Acceptance:** Each live E2E test case in `test_e2e_llm.py` resets the store before ingesting its fixture so every assertion runs on a clean context and avoids cross-test accumulation.

**Autotest when passed:** `tests/test_e2e_llm.py` (helper `_reset_and_ingest` used by all four tests), validated in full `pytest tests/` run.

---

## Issue 20: Broken curl URL after path redaction in q5 follow-up

**Status:** PASSED

**Description:** In some q5 follow-up answers, grounding redaction could leave malformed examples like `https:/[use only endpoints from the documentation]`, which is not actionable for auditors.

**Acceptance:** When redaction touches URL examples, normalization replaces malformed placeholders with a grounded fallback URL using an allowed documented path (e.g. `https://api.example.com/<allowed-path>`).

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_replaces_broken_redacted_url_with_grounded_placeholder`

---

## Issue 21: Invalid BOLA confirmation when user A is denied

**Status:** PASSED

**Description:** Some generated instructions incorrectly said that if user A (owner) does not receive data then BOLA is confirmed. Denial to user A can indicate missing object, wrong environment, or auth mismatch and does not itself prove BOLA.

**Acceptance:** Normalization rewrites this logic to require object existence and proper two-user comparison; user-A denial alone must not be treated as confirmation.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_rewrites_invalid_user_a_denied_confirmation`

---

## Retraining / model improvements (when applicable)

- If prompt and RAG changes do not resolve the above, **retrain or adapt the model** using the tool's instruments:
  - **Training data:** Update `data/training/` and `data/knowledge/` (add BOLA-only examples, desired output format, verification-step phrasing). Regenerate with `PYTHONPATH=src python src/training/generate_data.py`.
  - **RAG:** Reload knowledge with `PYTHONPATH=src python src/training/load_knowledge.py` so the model sees the new examples in context.
  - **Ollama model:** Update `docker/Modelfile` (system prompt) and recreate the model: `ollama create bola-analyzer -f Modelfile`. For full fine-tuning, use `data/training/bola_training.jsonl` with Ollama or external tools.
- You can also update any part of the tool (prompts, post-processing in `agent/runner.py`, RAG, API) to enforce output shape or content when the LLM is inconsistent.
- Track in this file: "Model retraining: [x] not needed (prompt + post-processing resolved all issues) / [ ] planned / [ ] done (date)."

---

## Issue 22: [E2E-LOOP] Curl examples in multi-finding reports use wrong path

**Status:** PASSED

**Description:** When a response includes multiple findings, curl example paths for findings 2, 3, ... often reuse the path from finding 1 (the first retrieved RAG chunk) instead of the specific path for each finding. For example, a `PATCH /accounts/{accountId}/contact` finding's curl example shows `/accounts/{accountId}/usage` (another endpoint in the same document).

**Root cause:** Smaller models can anchor on the first retrieved path and copy it into subsequent curl examples without linking each curl to its finding heading.

**Fix:** Added deterministic output-shape enforcement in normalization for strict curl follow-ups (q5), and retained/extended curl-path correction logic tied to documented heading paths in `runner._normalize_report()`.

**Acceptance:** Curl output for strict follow-ups uses the exact documented path/method and no narrative drift.

**Autotests when passed:** `tests/test_agent.py::test_fix_curl_path_mismatch_replaces_wrong_path_in_finding`, `tests/test_agent.py::test_normalize_report_enforces_q5_two_curl_only_shape`, `tests/test_e2e_loop_failures.py::test_e2e_loop_issue_35_q5_returns_only_two_curl_commands`

---

## Issue 23: [E2E-LOOP] Benefits Portal — WP-017 through WP-020 discovered and fixed

**Status:** VERIFIED

**Session:** 2026-03-24 (agent prompt — Benefits Portal API — with per-response adaptive analysis)

**Doc fixture:** `shared_docs/doc_onetime_benefits_portal_20260324b.md`

**Expected risks:**
1. GET /employees/{employeeId}/benefits — read BOLA
2. PUT /employees/{employeeId}/beneficiary — write BOLA
3. GET /plans/{planId}/enrollment-history — plan admin BOLA
4. GET /companies/{companyId}/employees — list BOLA
5. POST /coverage-changes — body-field BOLA (submittingEmployeeId)

**Per-response adaptive analysis found:**
- WP-017: Hallucinated endpoint findings with redacted headings surviving in report → FIXED
- WP-018: Inverted rationale ("The server restricts this endpoint to...") → FIXED
- WP-019: GET curl examples with `-d submittingEmployeeId` body payloads → FIXED
- WP-020: Repeated `#### Rationale:` sub-blocks under same `###` finding → FIXED

**Final sign-off:** 12/12 quality checks PASS. 5/5 endpoint coverage. Unit test count: 52/52.

---

## BUG-001: ChromaDB batch size overflow on large documents (OPEN → FIXED)

**Reported:** User pulled fresh `ghcr.io/igorredkach/bolai:latest` image, ingested a large document via chat, and after ~5 minutes got:

```
chromadb.errors.InternalError: ValueError: Batch size of 15525 is greater than max batch size of 5461
```

**Root cause:** `DocStore.add_document()` in `src/bola_ai/rag/store.py` calls `self._collection.add()` with ALL chunk embeddings at once. ChromaDB enforces a hard max batch size of 5461. Large documents that produce more chunks crash the ingestion.

**Symptoms:**
1. Chat shows "Thinking..." spinner for several minutes (embedding runs)
2. No response returned to UI
3. Server crashes with `InternalError` after embedding completes

**Fix:** Batch the `_collection.add()` calls in `store.py` to add at most `CHROMA_MAX_BATCH` (5000) items per call.

## BUG-002: OLLAMA_HOST env var conflict in all-in-one image (OPEN → FIXED)

**Reported:** Fresh all-in-one image shows "Starting up" banner; health check may report Ollama as offline.

**Root cause:** `docker/Dockerfile.allinone` sets `OLLAMA_HOST=http://127.0.0.1:11434`. The Ollama binary uses this env var as its **bind address**, but expects the format `host:port` (no scheme). The Python app reads it as a base URL and expects `http://...`. Using a single env var for both purposes can cause the Ollama server to fail to parse the address.

**Fix:** Use separate env vars: `OLLAMA_HOST=127.0.0.1:11434` (for Ollama binary) and `OLLAMA_BASE_URL=http://127.0.0.1:11434` (for the Python app). Update `config.py` to prefer `OLLAMA_BASE_URL` over `OLLAMA_HOST`.

---

## BUG-003: Analysis guard never triggers — LLM hallucinates from training data (OPEN → FIXED)

**Reported:** User loaded fresh image with their network logs in the shared folder, asked BOLA questions, and got hallucinated analysis about "patient APIs" and "prescriptions" that had nothing to do with their documents.

**Root cause:** The analysis guard (`store.count() == 0` at line 348 of `app.py`) never triggers because the RAG knowledge preload adds ~439 chunks of generic BOLA training examples to the store at startup. Since `count()` includes both preloaded knowledge AND user documents, the guard thinks documents are loaded and sends the query to the LLM, which retrieves generic training examples and hallucinates.

**Symptoms:**
1. User places files in shared folder and starts container
2. Files are never auto-ingested
3. User asks a question — gets "analysis" based on training patterns, not their documents
4. Results mention endpoints/APIs not present in the user's documentation

**Fix:**
1. Track user-ingested document sources separately (`_user_doc_sources` set)
2. Change analysis guard to check `_user_doc_sources` instead of `store.count()`
3. Auto-ingest files from `/shared-docs` on app startup
4. Broaden ingest trigger phrases to match natural language ("get my files", "investigate", "take a look", "scan", etc.)
5. Add `source_filter` to `DocStore.search()` — when analyzing, only retrieve chunks from user-ingested documents, preventing training data from contaminating results

---

## BUG-004: Auto-ingest blocks server startup — tool unresponsive on fresh image (OPEN → FIXED)

**Reported:** User pulled fresh `ghcr.io/igorredkach/bolai:latest`, placed a file in shared docs, started container. Logs show "Auto-ingest: found 1 file(s)..." then the embedder model loading (~2 min), then "RAG store ready; chunks=439" — but the server never starts serving HTTP requests.

**Root cause:** `_auto_ingest_shared_docs()` ran synchronously inside the FastAPI `lifespan` context manager. The lifespan doesn't `yield` (i.e., the server doesn't start accepting connections) until auto-ingest completes. In the all-in-one image, the first call to `get_store()` triggers real embedder model loading (~2 min), then `add_document()` embeds all user doc chunks (more minutes). Total startup block: 3-5+ minutes during which the server is completely dead.

**Why it was missed in testing:**
1. Unit tests use `FakeEmbedder` — instant, no real model loading
2. Dev Docker stack has the embedder model cached — loads in seconds
3. Only the fresh all-in-one image (the user's actual deployment path) hits the cold-start delay
4. No test existed that validated the server becomes responsive during auto-ingest

**Fix:** Move auto-ingest into a background `threading.Thread(daemon=True)` that starts during lifespan but doesn't block the `yield`. The server starts serving immediately. The health endpoint reports `auto_ingest_status` so the UI shows progress.

**Process improvement:** Add goal requiring that any feature touching startup must be tested against the actual all-in-one image flow, not just the dev stack.

---

## BUG-005: Ollama context window truncation — prompts silently clipped at 4096 tokens (FIXED)

**Reported:** User ran `analyze har.txt` on fresh image. Ollama logs show `truncating input prompt limit=4096 prompt=4882 keep=4 new=4096`. The system prompt + RAG context (10 chunks) + user query exceeded the default 4096 token KV cache, causing silent truncation and degraded analysis quality.

**Root cause:** Neither the Modelfile nor the `llm.py` API client set `num_ctx`. Ollama defaults to `n_ctx=4096`. With 10 RAG chunks (~5000 chars = ~1200 tokens) + system prompt (~600 tokens) + user query, the total frequently exceeds 4096.

**Fix:** Add `"num_ctx": 8192` to the `options` dict in `llm.py` `chat()`. The Qwen 2.5 Coder 1.5B model supports up to 32768 tokens; 8192 is sufficient and memory-efficient (~224 MB KV cache vs ~112 MB at 4096).

**Status:** FIXED

---

## BUG-006: Race condition in get_store() — auto-ingest and health endpoint initialize store simultaneously (FIXED)

**Reported:** Fresh all-in-one image with file in shared_docs/. Logs show two concurrent `Initializing RAG store at /data/chroma` messages 0.1s apart, then `Auto-ingest: failed to initialize store: '/data/chroma'`. The auto-ingest thread and the first health check both call `get_store()` at the same time, both see `_store is None`, and both try to create a DocStore. ChromaDB's SQLite backend rejects the second concurrent connection.

**Root cause:** `get_store()` was not thread-safe. No lock protected the singleton initialization. With FastAPI's lifespan spawning a background thread (auto-ingest) while the web server starts accepting health checks, two threads race to initialize the store.

**Fix:** Add `_store_lock = threading.Lock()` and use double-checked locking in `get_store()`: check `_store is not None` before acquiring lock, then check again inside the lock to prevent duplicate initialization.

**Status:** FIXED

---

## BUG-007: Analysis quality regression — HAR and complex documents produce garbage output (FIXED)

**Reported:** User's HAR file analysis went from excellent Salesforce/GraphQL BOLA findings to generic template output ("REST Path Analysis", "SQL Analysis"). Multiple compound root causes identified.

**Root causes:**
1. RAG search used user's raw message (e.g. "analize har.txt") as embedding query — found wrong chunks
2. Only 10 chunks of 512 chars = ~5KB context for 100KB+ HAR files
3. HAR JSON chunked as raw text — meaningless fragments
4. Normalization stripped valid "Additional Notes" and GraphQL content
5. Path grounding too aggressive for HAR/Salesforce contexts

**Fixes:**
1. BOLA-focused RAG search query + secondary search with user query, merged
2. Default chunks increased from 10 to 20
3. HAR JSON preprocessing: detects and converts to readable API summary before chunking
4. "Additional Notes" preserved
5. Normalization skipped for HAR/JSON/Salesforce/GraphQL contexts
6. Fixed GraphQL detection for Salesforce-style contexts

**Status:** FIXED

---

## BUG-008: Large real-world HAR files produce 15K+ chunks and timeout (FIXED)

**Reported:** User's real HAR file (6.9 MB, real Salesforce browser capture) produced 15,525 raw JSON chunks.
Ingestion took 9 minutes, then auto-analysis timed out at 300s. Chat queries also timed out.

**Root causes:**
1. HAR preprocessing didn't filter static assets (JS, CSS, images, fonts) — all entries were processed
2. No cap on HAR entries — 15K+ chunks overwhelmed embeddings and search
3. Auto-analysis timeout too short (300s) for CPU inference with rich context
4. Chat timeout (300s) too short for CPU inference
5. HAR detection only checked first 200 chars — real HAR files may have `"log"` further in

**Fixes:**
1. HAR preprocessor filters static assets by extension and MIME type
2. Only API-like requests kept (POST/PUT/PATCH/DELETE, JSON, GraphQL, Aura, /api/, /services/)
3. Max 200 HAR entries processed
4. Auto-analysis timeout: 900s; chat timeout: 600s; analyze client timeout: 660s
5. HAR detection checks first 1000 chars for `"log"` key

**Status:** FIXED

---

## BUG-009: Docker image quality baseline mismatch vs expected BOLA reasoning (PASSED)

**Reported:** User compared output from the Docker image ("REST Path Analysis", "GraphQL Operation Analysis", generic templated garbage) against previous detailed analysis (Salesforce OWD/FLS reasoning, attack chains, PII identification, specific record IDs). The Docker image was downloading a clean `qwen2.5-coder:1.5b` model at runtime and only adding a system prompt — no fine-tuning, no embedded knowledge beyond RAG.

**Root causes:**
1. `qwen2.5-coder:1.5b` (1.5 billion parameters) simply cannot reason about complex security concepts like Salesforce OWD, FLS, attack chains, PII exposure, or construct nuanced BOLA findings
2. Model was downloaded fresh at runtime — not pre-baked, adding startup delay and requiring internet
3. Only 2 CPU threads detected by Ollama — slow inference compounded with low quality
4. Context window (8192) and output limit (2048 tokens) too small for detailed analysis
5. No "teaching" beyond a system prompt — the model starts from zero every time

**Fixes:**
1. Standardized runtime and image defaults to smaller local model class (`qwen2.5-coder:3b`) for client-hardware compatibility.
2. Kept pre-baked model workflow in all-in-one build (offline runtime, no runtime pull dependency).
3. Added phase-1 teaching contract + gate cycle for higher quality on smaller model without larger-model fallback.
4. Added strict q5/q6 output-shape enforcement and regressions to prevent low-value narrative drift in adaptive E2E.

**Status:** PASSED — small-model baseline policy implemented end-to-end and verified by adaptive E2E + regression tests.

---

## BUG-010: Structured HAR/Salesforce outputs became over-normalized and unusable (FIXED)

**Reported:** Fresh Docker image produced low-value templated output with odd placeholders/redactions (for example broken path placeholders in curl and generic cross-technology sections) even when HAR content contained concrete Salesforce/GraphQL evidence.

**Root causes:**
1. `_normalize_report()` applied hallucinated REST prefix redaction to structured HAR/Salesforce contexts, which could hide valid paths and degrade examples.
2. Startup auto-analysis used a generic query that encouraged broad template output instead of source-specific findings.
3. Entrypoint could silently fall back to runtime model pull/create when expected pre-baked model was missing, making behavior inconsistent with offline/quality expectations.

**Fixes:**
1. Skip aggressive hallucinated-prefix/title redaction for structured contexts (`HAR`, `Salesforce`, `GraphQL`, `Aura`) in `src/bola_ai/agent/runner.py`.
2. Keep actionable `Fix steps` sections in normalized reports (do not strip useful remediation content).
3. Use a stricter, source-grounded startup auto-analysis query in `src/bola_ai/api/app.py`.
4. Harden all-in-one entrypoint: fail fast if baked model is missing unless explicit opt-in fallback (`BOLA_AI_ALLOW_MODEL_PULL=1`).

**Autotests:**  
`tests/test_agent.py::test_normalize_report_structured_context_does_not_redact_real_api_paths`  
`tests/test_agent.py::test_normalize_report_keeps_fix_steps_sections`  
`tests/test_agent.py::test_normalize_report_keeps_plain_fix_steps_bullet`  
`tests/test_api.py::test_auto_ingest_on_startup`

**Status:** FIXED

---

## BUG-011: Live larger-model inference timeouts in full regression runs (FIXED)

**Status:** FIXED

**Reported:** During full-cycle validation on a larger model class, long live tests (`test_api_live.py`, `test_issues_resolved.py`) can hit client read timeouts before completion, especially after repeated analyze calls in one run.

**Observed symptoms:**
1. `POST /analyze` occasionally exceeds 420-660s in live regression tests.
2. Full `pytest tests/` becomes unstable due long inference windows.
3. Adaptive/manual E2E can stall if query scope is broad.

**Fixes applied:**
1. Runtime tuning defaults: explicit thread/cap settings (`BOLA_AI_NUM_THREAD`, `BOLA_AI_OLLAMA_NUM_CTX`, `BOLA_AI_OLLAMA_NUM_PREDICT`, `BOLA_AI_N_CONTEXT`, `BOLA_AI_MAX_CONTEXT_CHARS`).
2. Startup auto-analysis preserved (enabled by default) and contention controlled by serializing analyze calls with an API-level analysis lock; live tests now wait for startup auto-analysis to settle before issuing benchmark analyze calls.
3. Auto-analysis query/timeout reduced in API code for safer behavior when enabled (`_AUTO_ANALYZE_QUERY` simplified; timeout lowered to 300s).
4. Live tests hardened to use configured client timeout and concise retry behavior.

**Acceptance (to close):**
1. `PYTHONPATH=src pytest tests/test_api_live.py::TestLiveAPI::test_live_ingest_then_analyze -q` passes (64s).
2. `PYTHONPATH=src pytest tests/test_issues_resolved.py -q` passes (10 tests).
3. Adaptive E2E completed 4 interactive turns on `doc_onetime_transit_cards_20260331.md` without forced termination; responses grounded to fixture endpoints.

**Autotest when passed:**
- `tests/test_api_live.py::TestLiveAPI::test_live_ingest_then_analyze`
- `tests/test_issues_resolved.py` (full file)

---

## Issue 26: [E2E-LOOP] Trailing truncated heading appears before verification reminder

**Status:** PASSED

**Description:** In adaptive follow-up responses, model output could end with a dangling partial finding heading (for example `### GET /api`) just before the appended verification reminder. This creates malformed/truncated output for auditors.

**Acceptance:** Normalization removes trailing dangling `###` finding headings when they are incomplete and appear immediately before the verification reminder block.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_removes_dangling_trailing_heading_before_reminder`

---

## Issue 27: [E2E-LOOP] Outcome interpretation inversion labels 403 as vulnerable

**Status:** PASSED

**Description:** In adaptive runbook-style answers, model could output `Vulnerable Outcome (403 Forbidden)`, which inverts authorization semantics. For unauthorized user tests, `403` indicates enforcement and should not be labeled as vulnerability.

**Acceptance:** Normalization rewrites `Vulnerable Outcome (403 Forbidden)` to `Secure Outcome (403 Forbidden)` in generated report text.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_relabels_403_as_secure_outcome`

---

## Issue 28: [E2E-LOOP] Generic meta headings leak into findings section

**Status:** PASSED

**Description:** Adaptive outputs can include generic meta headings (for example `### Potential BOLA findings with rationale and verification steps`) and fixture title lines, which are not endpoint findings and reduce auditor clarity.

**Acceptance:** Normalization strips these generic meta headings while preserving real endpoint findings.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_strips_generic_meta_headings`

---

## Issue 29: [E2E-LOOP] Adaptive runbook replies can truncate near end of response

**Status:** PASSED

**Description:** Live adaptive runbook prompts may get truncated when compose runtime sets `BOLA_AI_OLLAMA_NUM_PREDICT=512`, producing cut example blocks and incomplete final sections.

**Acceptance:** Compose defaults align with application baseline (`768`) to reduce truncation risk while preserving stable runtime.

**Validation when passed:** Updated defaults in `docker/docker-compose.yml` and root `docker-compose.yml` to `BOLA_AI_OLLAMA_NUM_PREDICT=768`; rechecked live adaptive response quality.

---

## Issue 30: [E2E-LOOP] Placeholder path leaks as `Path: [use only endpoints from the documentation]`

**Status:** PASSED

**Description:** Tool output can contain a literal placeholder line `Path: [use only endpoints from the documentation]`, which is not actionable for auditors.

**Analysis (test data vs tool logic):**
- **Primary cause is tool logic**, not fixture content.
- Existing normalization already repaired malformed placeholder **URLs** (Issue 20), but did not repair standalone `Path:` fields.
- When unknown paths are redacted, `Path:` lines could remain as raw placeholders.

**Acceptance:** If a `Path:` field is placeholder-only, normalization replaces it with a grounded fallback path from allowed documentation paths.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_repairs_redacted_path_field_with_fallback`

---

## Issue 31: [E2E-LOOP] Path-audit output includes placeholder-only NO lines

**Status:** PASSED

**Description:** In q6 self-path-validation style responses, output could include non-actionable lines like `- **NO** [use only endpoints from the documentation]` or `- **NO** GET [use only endpoints from the documentation]`.

**Acceptance:** Normalization removes placeholder-only `NO` path-audit lines while preserving meaningful entries.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_strips_placeholder_only_no_lines_in_path_audit`

---

## Issue 32: Live analyze can collapse to near-empty report when allowed `/api/users/{id}` is over-redacted

**Status:** PASSED

**Description:** A live test query with ingested path `/api/users/{id}` could produce a near-empty normalized report (`## Potential findings` + dangling code fence). Root cause was unconditional normalization redaction of `/api/...users|tenants...` paths before allowed-path grounding.

**Acceptance:** Allowed user paths from ingested docs are preserved; unknown paths are still handled by normal allowed-path grounding logic.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_keeps_allowed_users_path`, plus `tests/test_api_live.py::TestLiveAPI::test_live_ingest_then_analyze`

---

## Issue 33: Intermittent near-empty report with dangling code fence in live analyze

**Status:** PASSED

**Description:** Live smoke analyze could occasionally return a near-empty normalized report (`## Potential findings` + dangling ```) which fails quality expectations and breaks live smoke assertions.

**Acceptance:** Normalization strips dangling trailing code fences and emits a minimal actionable fallback body when output is too short.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_recovers_from_dangling_fence_near_empty_output`, validated with `tests/test_api_live.py::TestLiveAPI::test_live_ingest_then_analyze`

---

## Issue 34: [E2E-LOOP] q6 path-audit can still emit numbered placeholder lines

**Status:** PASSED

**Description:** In some self-path-validation outputs, placeholders were emitted as numbered lines (for example `1. [use only endpoints from the documentation] — **NO**`) and bypassed prior bullet-only cleanup logic.

**Acceptance:** Normalization strips placeholder path-audit lines in both bullet and numbered formats.

**Autotest when passed:** `tests/test_agent.py::test_normalize_report_strips_numbered_placeholder_path_audit_lines`

---

## BUG-012: Startup auto-analysis lock contention can block `/api/chat` and end in timeout

**Status:** PASSED

**Reported:** Pulled latest image timed out on a small doc; logs show startup auto-analysis failing with `ReadTimeout` and chat request taking 5m before 500.

**Root cause:**
1. Startup auto-analysis used the same serialized foreground analysis lock as interactive `/api/chat` and `/analyze`.
2. If auto-analysis stalled/timed out, foreground chat waited behind it and inherited poor UX/failures.
3. Startup auto-analysis context/timeout were not explicitly tuned for "fast-first-result" behavior.

**Fixes:**
1. Startup auto-analysis no longer uses foreground serialized analysis lock; foreground requests are no longer blocked behind background startup analysis.
2. Added dedicated startup tuning config: `BOLA_AI_AUTO_ANALYZE_TIMEOUT`, `BOLA_AI_AUTO_ANALYZE_N_CONTEXT`.
3. Added startup source limiting (`BOLA_AI_AUTO_ANALYZE_MAX_SOURCES`) so startup analysis runs on a bounded subset for responsiveness when many docs are mounted.
4. Chat/analyze now return immediate informational/busy responses while startup auto-analysis is running instead of waiting into timeout paths.
5. Kept foreground lock for user requests to avoid interactive request pileups, but decoupled background startup work from it.
6. Added regression tests for non-locking startup path and source-limit behavior.

**Acceptance:** Pull/run image with shared docs should keep `/api/chat` responsive even if startup auto-analysis is slow/fails; no 5-minute lock-wait blockage behind startup analysis.

**Autotests when passed:** `tests/test_api.py::test_auto_ingest_and_analyze_does_not_use_foreground_analysis_lock`, `tests/test_api.py::test_auto_ingest_and_analyze_limits_sources_for_startup_pass`, `tests/test_api.py::test_chat_returns_info_when_startup_auto_analysis_running`, `tests/test_api_live.py::TestLiveAPI::test_live_ingest_then_analyze`

---

## Issue 35: [E2E-LOOP] q5 strict two-curl format ignored on small-model baseline

**Status:** PASSED

**Description:** In the standard adaptive run (`docs/e2e_loop_last_run.json` on 2026-04-03), q5 requires exactly two curl commands (Token A / Token B, same method/path). The response drifted to narrative findings and did not return the required strict two-command format.

**Acceptance:** q5 response contains exactly two curl commands only (no extra findings prose), with the same documented endpoint path and method for token A and token B.

**Autotest when passed:** `tests/test_e2e_loop_failures.py::test_e2e_loop_issue_35_q5_returns_only_two_curl_commands`

**Verification evidence:** `docs/e2e_loop_last_run.json` now contains:
- `report_q5_fake_curls_full`: exactly two curl commands only
- same path/method for token A and token B (`POST /graphql`)

---

## Issue 36: [E2E-LOOP] q6 path-audit output shape ignored on small-model baseline

**Status:** PASSED

**Description:** In the same adaptive run (`docs/e2e_loop_last_run.json`), q6 requires compact path audit lines (`path -> YES/NO`). The response returned full finding sections and partial truncation instead of the requested path-audit list.

**Acceptance:** q6 response is path-audit only: list every cited path from q5 and mark YES/NO against ingested documentation grounding, without full finding sections.

**Autotest when passed:** `tests/test_e2e_loop_failures.py::test_e2e_loop_issue_36_q6_returns_path_audit_only`

**Verification evidence:** `docs/e2e_loop_last_run.json` now contains:
- `report_q6_validate_paths_full`: compact path-audit only output
- no full findings sections/truncation in q6 response

---

## Issue 40: Context window utilization mismatch (`n_ctx_seq` below model train context)

**Status:** OPEN

**User-reported symptom:** Logs show `n_ctx_seq (8192) < n_ctx_train (32768) -- the full capacity of the model will not be utilized`.

**Why this matters:** This is not a crash, but it is an important quality/capacity concern. Lower runtime context can improve speed, but may degrade long-document reasoning (HAR/Salesforce) and can look like an underconfigured model on capable hardware.

**Current gap:**
1. No benchmarked policy in repo for when to run 8k vs 16k vs 32k context.
2. E2E does not enforce context-capacity checks against long fixtures.
3. Runtime defaults are not tied to measured quality/latency trade-offs on this hardware profile.

**Acceptance:**
1. Add reproducible benchmark evidence (quality + latency) for at least 8k/16k/32k on long fixture(s).
2. Document and enforce selected default/profile in config/docs.
3. Add regression guard for chosen context policy.

**Autotest/validation target:** add benchmark evidence under `docs/live_e2e_test_timings.md` (or dedicated perf doc) plus config-policy test.

---

## Issue 41: [E2E-LOOP] REST fixture q3 response hallucinates GraphQL operations

**Status:** OPEN

**Fixture:** `tests/fixtures/doc_onetime_supply_chain_api.md`

**Observed bad response (`docs/e2e_loop_last_run.json`, `report_q3_full` from live run):**
1. Invented GraphQL mutation `updateShipmentStatus` although fixture is REST-only.
2. Mixed wrong endpoint/method semantics (shipment path with bulk request body shape).
3. Added non-grounded generic security claims not tied to explicit fixture evidence.

**Impact:** Follow-up guidance becomes untrustworthy; auditors can execute invalid tests.

**Acceptance:**
1. For q3 wording "If the doc has GraphQL...", non-GraphQL fixtures must explicitly return "not applicable" and remain REST-grounded.
2. No GraphQL tokens/operations in q3 response when fixture has no GraphQL.
3. Add dedicated e2e-loop regression test for this scenario.

**Autotest target:** new test in `tests/test_e2e_loop_failures.py`.

---

## Issue 42: [E2E-LOOP] Runbook response still inverts BOLA outcome interpretation

**Status:** OPEN

**Observed in live E2E (`report_q4_detail_runbook_full`):**
1. In supply-chain runbook: `A=200` and `B=403` interpreted as confirmed BOLA/BAC (incorrect).
2. In Salesforce HAR-like runbook: contradictory wording maps `403` to missing authorization in places.
3. Runbook sometimes uses different object IDs rather than same-object two-user comparison.

**Impact:** High-severity logic error; can produce false positives in security testing conclusions.

**Acceptance:**
1. q4 runbook must consistently interpret `A=200, B=403/404` as likely enforced access control (not confirmed BOLA).
2. q4 must require same-object two-user comparison.
3. Add e2e-loop regression for q4 interpretation rules.

**Autotest target:** new q4 regression in `tests/test_e2e_loop_failures.py`.

---

## Issue 43: [E2E-LOOP] E2E harness under-validates response correctness and grounding

**Status:** PASSED

**Problem:** `scripts/run_agent_e2e_loop_once.py` historically recorded outputs but did not assert critical quality failures (hallucinated operations, invalid BOLA logic, unknown paths in q1-q4), so a run could appear complete while quality was unacceptable.

**Resolution (2026-04-06):**
1. Added `_check_logical_correctness(query, report)` to `scripts/run_agent_e2e_loop_once.py` — detects whether the response type matches the question type (runbook → numbered steps; curl-generation → ≥2 curls with two tokens; path-audit → YES/NO entries; request-generation → curl with auth; security analysis → findings/rationale; GraphQL → steps or "not applicable").
2. Per-step `logical_match` and `logical_notes` in the step log; `automated_checks.logical_correctness_summary` captures all failures at the end of the run.
3. Terminal output explicitly lists logical correctness failures so they are visible to the agent.
4. `_audit_response` already provided per-step unknown-path and suspicious-phrase tracking for q1-q4; now complemented by logical correctness.
5. Tests added in `tests/test_e2e_script_audit.py` (8 logical-correctness tests + 1 audit test).
6. `docs/E2E_TESTING.md` updated with per-response logical correctness table.
7. `docs/AGENT_PROMPT_FULL_CYCLE.md` updated with R0 check in the per-response checklist.

**Autotests when passed:** `tests/test_e2e_script_audit.py` (all 9 tests); live evidence in `docs/e2e_loop_last_run.json` (`automated_checks.logical_correctness_summary.all_logical_matches = true`).

---

## Issue 44: [E2E-LOOP] Initial broad analysis query can monopolize lock for 2+ minutes

**Status:** OPEN

**Evidence (local dev stack, 2026-04-06):**
1. Manual q1 probe (`"As a security reviewer reading this API doc only..."`) remained running for ~133s and was manually terminated.
2. During that interval, fast-path follow-up requests queued on analyze lock (`Analyze lock: waiting`) despite being deterministic/low-cost.
3. Earlier full-loop runs showed 7–10 minute wall-clock for 6-step E2E when q1 dominates.

**Root cause hypothesis:**
1. Broad q1 prompt triggers long generative output with high token budget (`BOLA_AI_OLLAMA_NUM_PREDICT=768`) on CPU.
2. Foreground serialize lock means one long generation stalls all subsequent requests.

**Acceptance:**
1. Keep deterministic fast-path queries outside lock (implemented) and verify no queue wait for q3/q4/q5/q6-style prompts.
2. Add additional mitigation for q1-style long generations (token-budget/profile tuning or staged response strategy) with measured wall-clock reduction.
3. Record before/after timings for q1 and full 6-step loop.

**Autotest/validation target:** updated performance evidence in `docs/live_e2e_test_timings.md` + regression check for fast-path lock bypass.

---

## Issue 45: Full-request generation is incomplete for user asks like "please generate me full request for description change"

**Status:** PASSED

**User-facing failure:** When users ask for a complete request payload for a concrete action (for example updating description), responses can be partial: missing method, missing full path, missing headers, or missing JSON body shape.

**Why this is high impact:**
1. Users expect copy-pasteable requests for immediate verification.
2. Partial snippets increase test mistakes and reduce trust.
3. For REST workflows, curl should be the primary output format when request generation is explicitly requested.

**Observed quality gaps:**
1. Prompt/training favors narrative findings over strict request templates.
2. No deterministic fallback for "full request" wording when endpoint/action is known.
3. E2E checks focus on path grounding but not full request completeness.

**Acceptance:**
1. If user explicitly asks for a full request, output includes:
   - HTTP method
   - full URL/path
   - required headers (at minimum `Authorization`, and `Content-Type` for JSON body)
   - request body for write operations
2. For REST endpoints, output is curl-first by default.
3. Add regression tests for "full request for description change" style prompts.
4. Update training prompts/examples to reinforce full-request formatting.

**Autotest target:** `tests/test_agent.py::test_short_circuit_full_request_description_change_returns_complete_curl` + manual API check via `/analyze` with explicit description-change ask.

**Resolution notes (2026-04-06):**
1. Added deterministic fast path in `src/bola_ai/agent/runner.py` for explicit "full request" asks.
2. For REST requests, output is curl-first with method, path/full target, auth header, JSON header, and body for write methods.
3. Removed fake-host fallback in short-circuit curl generation when no grounded base URL exists (path-only output instead of `https://api.example.com`).

---
