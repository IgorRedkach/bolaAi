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

**Status:** PARTIALLY MITIGATED — `_fix_curl_path_mismatch()` now corrects wrong paths in fenced code blocks; inline paths in prose remain (1.5B model capacity limit)

**Description:** When a response includes multiple findings, curl example paths for findings 2, 3, ... often reuse the path from finding 1 (the first retrieved RAG chunk) instead of the specific path for each finding. For example, a `PATCH /accounts/{accountId}/contact` finding's curl example shows `/accounts/{accountId}/usage` (another endpoint in the same document).

**Root cause:** The 1.5B model anchors on the first retrieved context path and copies it into subsequent curl example blocks without reasoning about which path belongs to which finding.

**Workaround:** System prompt reinforced to explicitly instruct path accuracy per finding. Auditors should verify that each curl example's path matches its finding heading and substitute if needed. The finding title (heading) is always correct — only the curl path may be wrong.

**Acceptance:** Remains OPEN until a larger model or fine-tuning resolves this. No automated test exists for this (path correctness requires per-finding context linkage).

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
