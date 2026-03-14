# Open issues and improvement tracker

When an issue is fixed, mark it **PASSED** and add an autotest that would have failed before the fix. Autotests live in `tests/test_issues_resolved.py`.

**Run issue-resolution tests (E2E, real LLM):**
```bash
BOLA_AI_LIVE_URL=http://localhost:8000 PYTHONPATH=src pytest tests/test_issues_resolved.py -v -s
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

## Retraining / model improvements (when applicable)

- If prompt and RAG changes do not resolve the above, **retrain or adapt the model** using the tool's instruments:
  - **Training data:** Update `data/training/` and `data/knowledge/` (add BOLA-only examples, desired output format, verification-step phrasing). Regenerate with `PYTHONPATH=src python src/training/generate_data.py`.
  - **RAG:** Reload knowledge with `PYTHONPATH=src python src/training/load_knowledge.py` so the model sees the new examples in context.
  - **Ollama model:** Update `docker/Modelfile` (system prompt) and recreate the model: `ollama create bola-analyzer -f Modelfile`. For full fine-tuning, use `data/training/bola_training.jsonl` with Ollama or external tools.
- You can also update any part of the tool (prompts, post-processing in `agent/runner.py`, RAG, API) to enforce output shape or content when the LLM is inconsistent.
- Track in this file: "Model retraining: [x] not needed (prompt + post-processing resolved all issues) / [ ] planned / [ ] done (date)."
