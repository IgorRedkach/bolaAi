"""Tests for agent prompts and runner (with mocked LLM)."""
import json
from unittest.mock import patch

import pytest
from bola_ai.agent.prompts import build_analysis_prompt, BOLA_SYSTEM_PROMPT
from bola_ai.agent.runner import run_analysis, _normalize_report, _extract_paths_from_context, _fix_curl_path_mismatch
from bola_ai.rag.chunking import chunk_text, _preprocess_har
from bola_ai.rag.store import DocStore


def test_fix_curl_path_mismatch_replaces_wrong_path_in_finding():
    """WP-010: curl block using a wrong documented path for a finding must be corrected.

    The curl path must actually change, not just have service-requests survive in the heading.
    """
    allowed = ["/accounts/{accountId}/usage", "/service-requests", "/properties/{propertyId}/billing"]
    report = (
        "### POST /service-requests\n"
        "**Rationale:** Body field not verified.\n"
        "**Verification steps:** Use two tokens.\n"
        "```sh\n"
        'curl -X POST "https://api.example.com/accounts/{accountId}/usage" '
        '-H "Authorization: Bearer <tokenA>"\n'
        "```\n"
    )
    out = _fix_curl_path_mismatch(report, allowed)
    # The wrong path in the curl block must be replaced; /service-requests must appear in the corrected curl
    assert "/accounts/{accountId}/usage" not in out, (
        "Wrong path should be replaced in curl block, but it still appears in output"
    )
    assert "/service-requests" in out


def test_fix_curl_path_mismatch_leaves_correct_path_untouched():
    """WP-010: curl block using the correct path for its finding must not be altered."""
    allowed = ["/accounts/{accountId}/usage", "/service-requests"]
    report = (
        "### GET /accounts/{accountId}/usage\n"
        "**Rationale:** No ownership check.\n"
        "```sh\n"
        'curl -X GET "https://api.example.com/accounts/acct-4821/usage" '
        '-H "Authorization: Bearer <tokenA>"\n'
        "```\n"
    )
    out = _fix_curl_path_mismatch(report, allowed)
    # Correct path must remain untouched
    assert "/accounts/acct-4821/usage" in out or "/accounts/{accountId}/usage" in out


def test_extract_paths_includes_meaningful_single_segment_paths():
    """Single-segment paths like /coverage-changes (≥4 chars) must be extracted for the WP-010 mitigation."""
    ctx = "### POST /coverage-changes\nSubmits a coverage change request."
    paths = _extract_paths_from_context(ctx)
    assert "/coverage-changes" in paths


def test_extract_paths_excludes_short_version_prefix():
    """Short single-segment paths like /v2 or /v3 must NOT be extracted."""
    ctx = "Base URL: https://api.example.com/v2"
    paths = _extract_paths_from_context(ctx)
    assert "/v2" not in paths


def test_extract_paths_excludes_domain_segments():
    """WP-009: domain-name-like segments (e.g. /api.waterdistrict.gov/v2) must not be returned as paths."""
    context = (
        "**Base URL:** `https://api.waterdistrict.gov/v2`\n"
        "### GET /v2/accounts/{accountId}/usage\n"
        "### PATCH /v2/accounts/{accountId}/contact\n"
    )
    paths = _extract_paths_from_context(context)
    # Domain-looking segments must be excluded
    assert not any("api.waterdistrict.gov" in p for p in paths), f"domain segment leaked: {paths}"
    # Real API paths must still be present
    assert any("accounts" in p for p in paths), f"real paths missing: {paths}"


def test_system_prompt_contains_bola():
    assert "BOLA" in BOLA_SYSTEM_PROMPT
    assert "verification" in BOLA_SYSTEM_PROMPT.lower()


def test_build_analysis_prompt():
    prompt = build_analysis_prompt("Some API spec.", query="Find risks.")
    assert "Some API spec" in prompt
    assert "Find risks" in prompt
    assert "Mandatory grounding" in prompt
    assert "verbatim" in prompt.lower()


@patch("bola_ai.agent.runner.chat")
def test_run_analysis_mocked(mock_chat, store):
    store.add_document("GET /api/patients/1 returns patient data.", source="test")
    mock_chat.return_value = "## Finding\nPossible BOLA: no ownership check."
    out = run_analysis(store, query="Any BOLA?")
    assert "BOLA" in out or "ownership" in out
    mock_chat.assert_called_once()
    call_args = mock_chat.call_args[0][0]
    assert len(call_args) >= 2
    assert any("system" in m.get("role", "") for m in call_args)
    assert any("user" in m.get("role", "") for m in call_args)


def test_normalize_report_rewrites_invalid_404_bola_confirmation():
    raw = (
        "## Potential findings\n\n"
        "### Sample\n"
        "**Verification steps:** If both requests return a 404 error, BOLA is confirmed."
    )
    out = _normalize_report(raw)
    lower = out.lower()
    assert "404 error, bola is confirmed" not in lower
    assert "bola is not confirmed" in lower


def test_normalize_report_redacts_paths_not_in_allowed_context():
    raw = (
        "## Potential findings\n\n"
        "### Wrong endpoint\n"
        "**Verification steps:** Call GET /api/v1/patients/123 with token A and B.\n"
        "Also call GET /banking/v1/accounts/123 with token A and B."
    )
    out = _normalize_report(raw, allowed_paths=["/banking/v1/accounts/{accountId}"])
    assert "/banking/v1/accounts/123" in out
    assert "/api/v1/patients/123" not in out
    assert "[use only endpoints from the documentation]" in out


def test_normalize_report_rewrites_invalid_401_bola_confirmation():
    raw = (
        "## Potential findings\n\n"
        "### Sample\n"
        "**Verification steps:** If the endpoint responds with a 401 Unauthorized error, BOLA is confirmed."
    )
    out = _normalize_report(raw)
    lower = out.lower()
    assert "401 unauthorized error, bola is confirmed" not in lower
    assert "does not confirm bola" in lower


def test_normalize_report_fixes_graphql_heading_bleed():
    """Heading bleed '**Title**# **Rationale:**' should be separated, not left corrupt (Issue 12)."""
    raw = (
        "## Potential findings\n\n"
        "### user(id) query\n"
        "**Rationale**# **Verification Steps:**\n"
        "1. Call with token A."
    )
    out = _normalize_report(raw)
    # The '**# **' pattern should be gone
    assert "**#" not in out
    # Rationale and Verification should both be present and separated
    assert "Rationale" in out
    assert "Verification Steps" in out


def test_normalize_report_fixes_graphql_auth_only_verification():
    """GraphQL verification saying 'token without required permissions' is auth, not BOLA (Issue 12)."""
    raw = (
        "## Potential findings\n\n"
        "### deleteDocument(id)\n"
        "**Verification steps:**\n"
        "Use a token that does not have the required permissions to access the document.\n"
        "Verify that the mutation returns an error indicating that the caller is not authorized.\n"
    )
    out = _normalize_report(raw)
    lower = out.lower()
    assert "does not have the required permissions" not in lower
    assert "two different valid user tokens" in lower


def test_normalize_report_graphql_syntax_preserved():
    """GraphQL operation syntax in a report must not be corrupted by normalization (Issue 12)."""
    raw = (
        "## Potential findings\n\n"
        "### user(id) query\n"
        "**Verification steps:** Call `query { user(id: \"userB-id\") { name } }` "
        "with token A and with token B. If both return data, BOLA is confirmed.\n"
    )
    out = _normalize_report(raw)
    assert "user(id:" in out
    assert "token A" in out or "token a" in out.lower()


def test_normalize_report_strips_graphql_blocks_when_rest_only_doc():
    """REST-only docs must not show invented GraphQL code fences (WP-002 / WMS E2E)."""
    ctx = "REST only — no GraphQL. `POST /wms/v1/pick-tasks/{taskId}/complete`"
    raw = "## Potential findings\n\n```graphql\nquery { x { y } }\n```\n"
    out = _normalize_report(raw, context=ctx)
    assert "```graphql" not in out.lower()
    assert "does not define GraphQL" in out


def test_normalize_report_keeps_graphql_fence_when_doc_includes_graphql():
    ctx = "GraphQL usagePoint(id) and POST /energy/v2/accounts/bulk-usage"
    raw = "## x\n```graphql\nquery { usagePoint(id: \"1\") { id } }\n```\n"
    out = _normalize_report(raw, context=ctx)
    assert "usagePoint" in out
    assert "```graphql" in out.lower() or "query {" in out


def test_normalize_report_grounds_claims_only_doc():
    """When doc has only claims paths, report must not show Patient/Document API (Issue 15)."""
    allowed = ["/api/v2/claims/{claimId}", "/api/v2/policies/{policyId}/claims"]
    raw = (
        "## Potential findings\n\n"
        "### 1. Patient API may not check ownership\n"
        "**Verification steps:** Call GET /api/patients/123 with token A and token B.\n"
        "### 2. Document API may not check ownership\n"
        "**Verification steps:** Call GET /api/documents/456 with token A and token B.\n"
        "### 3. Claim API\n"
        "**Verification steps:** Call GET /api/v2/claims/789 with token A and token B.\n"
    )
    out = _normalize_report(raw, allowed_paths=allowed)
    assert "Patient API" not in out
    assert "Document API" not in out
    assert "Endpoint from documentation" in out
    assert "/api/patients/" not in out
    assert "/api/documents/" not in out
    assert "[use only endpoints from the documentation]" in out
    assert "/api/v2/claims/789" in out


def test_normalize_report_fixes_bearer_token_in_query_string():
    """Bearer must not appear in URL query; use Authorization header (Issue 16)."""
    raw = "**Example:** `GET /api/v2/loans/123?token=Bearer token1`"
    out = _normalize_report(raw)
    assert "?token=Bearer" not in out
    assert "Authorization" in out


def test_normalize_report_fixes_redacted_path_in_heading():
    """When path in ### title is redacted, heading should stay valid (Issue 15)."""
    allowed = ["/api/v2/claims/{claimId}"]
    raw = "### 4.[use only endpoints from the documentation]\n\n**Rationale:** Some text."
    out = _normalize_report(raw, allowed_paths=allowed)
    assert "### 4. Endpoint from documentation" in out
    assert "### 4.[use only" not in out


def test_normalize_report_fixes_post_instead_of_get_for_participants_and_site_log():
    """LLM sometimes emits POST for documented GET endpoints (agent E2E loop)."""
    allowed = [
        "/api/v2/participants/{participantId}",
        "/api/v2/sites/{siteId}/randomization-log",
    ]
    raw = "Call POST /api/v2/participants/p1 then POST /api/v2/sites/s9/randomization-log"
    out = _normalize_report(raw, allowed_paths=allowed)
    assert "POST /api/v2/participants" not in out
    assert "GET /api/v2/participants/p1" in out
    assert "GET /api/v2/sites/s9/randomization-log" in out


def test_normalize_report_replaces_broken_redacted_url_with_grounded_placeholder():
    allowed = ["/permits/v2/applications/{applicationId}"]
    raw = 'curl -X GET https:/[use only endpoints from the documentation] -H "Authorization: Bearer token_A"'
    out = _normalize_report(raw, allowed_paths=allowed)
    assert "https:/[use only endpoints from the documentation]" not in out
    assert "https://api.example.com/permits/v2/applications/{applicationId}" in out


def test_normalize_report_rewrites_invalid_user_a_denied_confirmation():
    raw = "If Alice does not receive data, BOLA is confirmed."
    out = _normalize_report(raw)
    low = out.lower()
    assert "bola is confirmed" not in low
    assert "does not confirm bola" in low


def test_normalize_report_strips_bola_remediation_cheat_sheet(
):
    """WP-006: BOLA Remediation Cheat Sheet from RAG knowledge must be stripped from reports."""
    raw = (
        "### GET /accounts/{accountId}/usage\n"
        "**Rationale:** No ownership check.\n\n"
        "## BOLA Remediation Cheat Sheet\n"
        "- Owner-check logic: authorize by object ownership or explicit permission.\n"
        "- Scope every query/update/delete with session identity.\n"
    )
    out = _normalize_report(raw)
    assert "BOLA Remediation Cheat Sheet" not in out
    assert "Owner-check logic" not in out
    assert "GET /accounts" in out  # real finding preserved


def test_normalize_report_strips_raw_notes_section():
    """WP-008: Raw '## Notes' / '### Notes' fixture sections must not appear as BOLA findings."""
    raw = (
        "### GET /accounts/{accountId}/usage\n"
        "**Rationale:** No ownership check.\n\n"
        "### Notes\n\n"
        "- REST only; no GraphQL or SOQL.\n"
        "- All IDs are opaque strings.\n"
        "- Rate limit: 60 requests per minute.\n\n"
        "### PATCH /accounts/{accountId}/contact\n"
        "**Rationale:** No ownership check on contact update.\n"
    )
    out = _normalize_report(raw)
    assert "Rate limit" not in out
    assert "REST only; no GraphQL" not in out
    assert "GET /accounts" in out
    assert "PATCH /accounts" in out


def test_normalize_report_strips_fix_steps_sections():
    """WP-007: 'Fix steps' sections generated by model are off-spec and inflate output — must be stripped."""
    raw = (
        "### PATCH /accounts/{accountId}/contact\n"
        "**Rationale:** No ownership check.\n"
        "**Verification steps:** Call with two tokens.\n"
        "**Fix steps:** Add owner-check logic in the controller.\n\n"
        "### GET /properties/{propertyId}/billing\n"
        "**Rationale:** Billing data exposed.\n"
    )
    out = _normalize_report(raw)
    assert "Fix steps" not in out
    assert "PATCH /accounts" in out
    assert "GET /properties" in out


def test_normalize_report_strips_plain_fix_steps_bullet():
    """WP-014: Plain-text '- Fix steps:' bullet (unbolded) must also be stripped."""
    raw = (
        "### GET /accounts/{accountId}/usage\n"
        "**Rationale:** No ownership check.\n"
        "**Verification steps:** Use two tokens.\n"
        "- Fix steps: Add an owner-check logic in the service layer.\n\n"
        "### PATCH /accounts/{accountId}/contact\n"
        "**Rationale:** No check on contact update.\n"
    )
    out = _normalize_report(raw)
    assert "Fix steps" not in out
    assert "GET /accounts" in out
    assert "PATCH /accounts" in out


def test_normalize_report_strips_python_code_block():
    """WP-012: Python/Django code blocks appearing in reports must be stripped."""
    raw = (
        "### PATCH /accounts/{accountId}/contact\n"
        "**Rationale:** No ownership check.\n"
        "**Verification steps:** Use two tokens.\n\n"
        "# Example of Python middleware to verify owner\n"
        "```python\n"
        "def verify_owner(request):\n"
        "    if request.user.is_authenticated:\n"
        "        return None\n"
        "```\n\n"
        "### GET /properties/{propertyId}/billing\n"
        "**Rationale:** Billing exposed.\n"
    )
    out = _normalize_report(raw)
    assert "def verify_owner" not in out
    assert "request.user.is_authenticated" not in out
    assert "PATCH /accounts" in out
    assert "GET /properties" in out


def test_normalize_report_strips_hallucinated_query_params():
    """WP-011: Hallucinated bypass query params (?owner=, ?tenant=, ?admin=) must be stripped."""
    raw = (
        "### GET /districts/{districtId}/accounts\n"
        "**Example:**\n"
        '```sh\ncurl -X GET "https://api.example.com/districts/dist-central/accounts'
        '?owner=acct-4821&tenant=tenant-1001&admin=true&uuid=uuid12345"\n```\n'
    )
    out = _normalize_report(raw)
    assert "owner=acct-4821" not in out
    assert "admin=true" not in out
    assert "uuid=uuid12345" not in out
    assert "GET /districts" in out


def test_normalize_report_strips_numbered_notes_section():
    """WP-013: Numbered '### 4. Notes' heading must be stripped like '### Notes'."""
    raw = (
        "### 3. GET /properties/{propertyId}/billing\n"
        "**Rationale:** No ownership check.\n\n"
        "### 4. Notes\n\n"
        "- REST only; no GraphQL or SOQL.\n"
        "- Rate limit: 60 requests per minute.\n\n"
        "### 5. GET /districts/{districtId}/accounts\n"
        "**Rationale:** List BOLA.\n"
    )
    out = _normalize_report(raw)
    assert "Rate limit" not in out
    assert "REST only; no GraphQL" not in out
    assert "GET /properties" in out
    assert "GET /districts" in out


def test_normalize_report_replaces_invalid_token_verification():
    """WP-015: 'Call with an invalid token' tests auth not BOLA — must be replaced with two-valid-user phrasing."""
    raw = (
        "**Verification steps:**\n"
        "1. Call the endpoint with a valid token.\n"
        "2. Call the same endpoint with an invalid token.\n"
        "3. If both return data, BOLA is confirmed.\n"
    )
    out = _normalize_report(raw)
    assert "invalid token" not in out.lower()
    assert "token b" in out.lower() or "different valid user" in out.lower()


def test_normalize_report_strips_redacted_heading_finding_blocks():
    """WP-017: Finding sections whose heading was redacted to [use only endpoints...] must be stripped entirely."""
    raw = (
        "### PUT /employees/{employeeId}/beneficiary\n"
        "**Rationale:** No ownership check.\n"
        "**Verification steps:** Use two tokens.\n\n"
        "### GET [use only endpoints from the documentation]\n"
        "**Rationale:** Some hallucinated finding.\n"
        "**Verification steps:** 1. Call with token.\n\n"
        "### PATCH [use only endpoints from the documentation]\n"
        "**Rationale:** Another hallucinated finding.\n\n"
        "### GET /companies/{companyId}/employees\n"
        "**Rationale:** List BOLA.\n"
    )
    out = _normalize_report(raw)
    # Hallucinated finding blocks must be gone
    assert "hallucinated finding" not in out.lower()
    assert "GET [use only" not in out
    assert "PATCH [use only" not in out
    # Real findings must remain
    assert "PUT /employees" in out
    assert "GET /companies" in out


def test_normalize_report_fixes_inverted_rationale():
    """WP-018: 'The server restricts this endpoint to X' is an inverted/wrong rationale and must be prefixed."""
    raw = (
        "### GET /plans/{planId}/enrollment-history\n"
        "### Rationale: The server restricts this endpoint to plan administrators or HR staff.\n"
        "**Verification steps:** Use two tokens.\n"
    )
    out = _normalize_report(raw)
    assert "No documentation states the server restricts" in out
    # The original "The server restricts" as a standalone assertion must not remain
    assert "Rationale: The server restricts" not in out


def test_normalize_report_strips_get_body_submitting_employee_id():
    """WP-019: GET curl examples must not include -d body payload with submittingEmployeeId."""
    raw = (
        "### GET /employees/{employeeId}/benefits\n"
        "**Verification steps:**\n"
        "```sh\n"
        "curl -X GET https://api.example.com/employees/emp-1042/benefits "
        "-H \"Authorization: Bearer tokenA\" -d '{\"submittingEmployeeId\": \"emp-1042\"}'\n"
        "```\n"
    )
    out = _normalize_report(raw)
    assert "submittingEmployeeId" not in out
    assert "/employees/emp-1042/benefits" in out or "/employees/" in out


def test_normalize_report_deduplicates_repeated_rationale_subheadings():
    """WP-020: Repeated #### Rationale: blocks under the same ### finding must be stripped after first."""
    raw = (
        "### GET /plans/{planId}/enrollment-history\n"
        "#### Rationale:\nNo ownership check.\n"
        "#### Verification steps:\nUse two tokens.\n"
        "#### Rationale:\nDuplicated rationale block.\n"
        "#### Verification steps:\nDuplicated verification block.\n"
    )
    out = _normalize_report(raw)
    assert out.count("#### Rationale:") == 1, f"Expected 1 Rationale block, got: {out.count('#### Rationale:')}"
    assert "Duplicated rationale block" not in out


def test_normalize_report_strips_grounding_suffix_echo():
    """WP-016: GROUNDING_USER_SUFFIX echoed verbatim by model must be stripped from reports."""
    raw = (
        "### GET /accounts/{accountId}/usage\n"
        "**Rationale:** No ownership check.\n\n"
        "**Mandatory grounding (person-style and runbook answers included):**\n"
        "- Every REST path must appear verbatim in the documentation.\n"
        "- Do not add endpoints not in the excerpt.\n"
    )
    out = _normalize_report(raw)
    assert "Mandatory grounding" not in out
    assert "Every REST path must appear verbatim" not in out
    assert "GET /accounts" in out

def test_normalize_report_preserves_additional_notes_section():
    """'Additional Notes' sections are preserved (they contain valuable HAR/Salesforce observations)."""
    raw = (
        "## Potential findings\n\n"
        "### GET /aid/v1/students/{studentId}/package\n"
        "**Rationale:** No ownership check.\n\n"
        "### Additional Notes\n\n"
        "- **GraphQL operations:** If the documentation mentions GraphQL...\n"
        "- **SOQL queries:** If the documentation mentions SOQL...\n"
    )
    out = _normalize_report(raw)
    assert "Additional Notes" in out
    assert "/aid/v1/students" in out


def test_har_preprocessing_extracts_api_summary():
    """HAR JSON is preprocessed into human-readable API summary before chunking."""
    har = json.dumps({
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.com/services/data/graphql",
                        "headers": [
                            {"name": "Authorization", "value": "Bearer eyJ0eXAi..."},
                            {"name": "Content-Type", "value": "application/json"},
                        ],
                        "postData": {
                            "text": json.dumps({
                                "query": "query getCaseComments($recordId: ID!) { uiapi { query { CaseComment(where: {ParentId: {eq: $recordId}}) { edges { node { Body { value } } } } } } }",
                                "variables": {"recordId": "500cT00000BPDwj"}
                            })
                        }
                    },
                    "response": {"status": 200, "content": {"text": '{"data": {"uiapi": {}}}'}}
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.com/api/v1/accounts/001cT00000DQOoo",
                        "headers": [{"name": "Authorization", "value": "Bearer eyJ0eXAi..."}],
                    },
                    "response": {"status": 200, "content": {"text": '{"accountId": "001cT00000DQOoo"}'}}
                }
            ]
        }
    })
    result = _preprocess_har(har)
    assert "POST https://example.com/services/data/graphql" in result
    assert "getCaseComments" in result
    assert "recordId" in result
    assert "GET https://example.com/api/v1/accounts/001cT00000DQOoo" in result

    # Verify chunking works on HAR input
    chunks = chunk_text(har)
    assert len(chunks) > 0
    assert any("getCaseComments" in c for c in chunks)


def test_har_preprocessing_returns_empty_for_non_har():
    """Non-HAR JSON should not be preprocessed."""
    assert _preprocess_har("not json") == ""
    assert _preprocess_har('{"foo": "bar"}') == ""


def test_normalize_report_deduplicates_repeated_findings():
    """WP-023: Duplicate ### finding headings (same endpoint repeated 3-4x by model) must be deduped."""
    raw = (
        "## Potential findings\n\n"
        "### GET /water/v2/customers/{customerId}\n"
        "**Rationale:** No ownership check.\n"
        "**Verification steps:** Use two tokens.\n\n"
        "### GET /water/v2/districts/{districtId}/customers\n"
        "**Rationale:** No district filter.\n\n"
        "### GET /water/v2/customers/{customerId}\n"
        "**Rationale:** No ownership check (repeated).\n\n"
        "### GET /water/v2/districts/{districtId}/customers\n"
        "**Rationale:** No district filter (repeated).\n\n"
        "### GET /water/v2/customers/{customerId}\n"
        "**Rationale:** Third copy.\n\n"
    )
    out = _normalize_report(raw)
    assert out.count("### GET /water/v2/customers/{customerId}") == 1
    assert out.count("### GET /water/v2/districts/{districtId}/customers") == 1
    assert "No ownership check." in out
    assert "No district filter." in out
    assert "repeated" not in out
    assert "Third copy" not in out

