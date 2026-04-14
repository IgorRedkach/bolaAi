"""Tests for E2E script response-audit helpers."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path


def _load_script_module():
    repo = Path(__file__).resolve().parents[1]
    script = repo / "scripts" / "run_agent_e2e_loop_once.py"
    spec = spec_from_file_location("run_agent_e2e_loop_once", script)
    assert spec and spec.loader
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_audit_response_flags_unknown_paths_and_suspicious_phrases():
    mod = _load_script_module()
    doc = (
        "GET /api/v3/shipments/{shipmentId}\n"
        "POST /api/v3/shipments/bulk\n"
    )
    report = (
        "### Finding\n"
        "Use GraphQL mutation updateShipmentStatus.\n"
        "If the endpoint returns 401 Unauthorized then it is vulnerable.\n"
        "Call /api/v9/secret/admin.\n"
    )
    audit = mod._audit_response(report, doc)
    assert "/api/v9/secret/admin" in audit["unknown_paths"]
    assert "401 unauthorized" in audit["suspicious_phrases"]
    assert "graphql mutation" in audit["suspicious_phrases"]


def test_audit_response_flags_placeholders_unbalanced_fences_and_duplicates():
    mod = _load_script_module()
    doc = "POST /css/s/sfsites/aura?r=11&aura.RecordUi.getRecordWithFields=1\n"
    report = (
        "## Potential findings\n"
        "### Cross-service identity propagation drift\n"
        "Bad token note [use only endpoints from documentation]\n"
        "```curl\ncurl -X POST https://api.example.com/aura\n"
        "### Cross-service identity propagation drift\n"
    )
    audit = mod._audit_response(report, doc)
    assert "placeholder_marker_detected" in audit["suspicious_phrases"]
    assert "unbalanced_code_fences" in audit["suspicious_phrases"]
    assert audit["duplicate_finding_titles"]


def test_audit_response_flags_har_aura_grounding_gaps():
    mod = _load_script_module()
    doc = (
        "POST /css/s/sfsites/aura?r=41&aura.RecordUi.executeGraphQL=1\n"
        "content-type: application/x-www-form-urlencoded; charset=UTF-8\n"
        "postData: message={...}&aura.context={...}&aura.token=eyJ...\n"
    )
    report = (
        "Use Authorization: Bearer token_A and Bearer token_B.\n"
        "POST /css/s/sfsites/aura?r=41&aura.RecordUi.executeGraphQL=1\n"
        "Potential operation listAccountsWithFields is vulnerable.\n"
    )
    audit = mod._audit_response(report, doc)
    assert "report_uses_bearer_abstraction_for_aura_form_flow" in audit["har_grounding_notes"]
    assert "report_missing_form_urlencoded_request_shape" in audit["har_grounding_notes"]
    assert "report_missing_aura_message_payload_shape" in audit["har_grounding_notes"]
    assert "listAccountsWithFields" in audit["unknown_operation_tokens"]


def test_check_logical_correctness_runbook_passes_with_numbered_steps():
    mod = _load_script_module()
    q = "For the highest-risk endpoint provide a numbered authorization test runbook."
    r = "## Authorization Test Runbook\n\n### POST /graphql\n\n1. Obtain token A.\n2. Call POST /graphql with token A.\n3. Obtain token B.\n4. Compare outcomes."
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "runbook"
    assert lc["logical_match"] is True


def test_check_logical_correctness_runbook_fails_without_numbered_steps():
    mod = _load_script_module()
    q = "For the highest-risk endpoint provide a numbered authorization test runbook."
    r = "This endpoint has BOLA risk. Use two tokens. Call with token A and token B."
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "runbook"
    assert lc["logical_match"] is False
    assert lc["notes"]


def test_check_logical_correctness_curl_generation_passes():
    mod = _load_script_module()
    q = "Give **only** two curl commands—Alice then Bob—same URL path."
    r = 'curl -X GET "https://api.example.com/orders/1" -H "Authorization: Bearer token_A"\ncurl -X GET "https://api.example.com/orders/1" -H "Authorization: Bearer token_B"'
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "curl_generation"
    assert lc["logical_match"] is True


def test_check_logical_correctness_curl_generation_fails_with_one_curl():
    mod = _load_script_module()
    q = "Give **only** two curl commands—Alice then Bob—same URL path."
    r = 'curl -X GET "https://api.example.com/orders/1" -H "Authorization: Bearer token_A"\nSome narrative text here.'
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "curl_generation"
    assert lc["logical_match"] is False


def test_check_logical_correctness_graphql_na_for_rest_only_doc():
    mod = _load_script_module()
    q = "If the doc has GraphQL, how should I verify authorization with two tokens on the same object id?"
    r = "No GraphQL operation is documented in the ingested artifact, so GraphQL-specific verification is not applicable.\n\nUse documented REST endpoints with two valid user tokens."
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "graphql_verification_or_na"
    assert lc["logical_match"] is True


def test_check_logical_correctness_security_analysis_passes_with_findings():
    mod = _load_script_module()
    q = "As a security reviewer reading this API doc: what are the top security risks?"
    r = "## Potential findings\n\n### BOLA: GET /api/orders/{orderId}\n**Rationale:** No documented ownership check.\n**Verification steps:**\n1. Token A...\n2. Token B..."
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "security_analysis"
    assert lc["logical_match"] is True


def test_check_logical_correctness_request_generation_passes():
    mod = _load_script_module()
    q = "Please generate me a full request to verify the description change endpoint."
    r = 'curl -X PATCH "https://api.example.com/api/v1/items/{itemId}" \\\n  -H "Authorization: Bearer <token_user_A>" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"description": "Updated description"}\''
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "request_generation"
    assert lc["logical_match"] is True


def test_check_logical_correctness_path_audit_passes():
    mod = _load_script_module()
    q = "Review your previous answer: list every HTTP path you cited. For each path, state YES if it appears in the ingested documentation text or NO if hallucinated."
    r = "## Path Audit\n- /api/v3/shipments/{shipmentId} -> YES\n- /api/v3/shipments/bulk -> YES\n- /api/v9/admin -> NO"
    lc = mod._check_logical_correctness(q, r)
    assert lc["question_type"] == "path_audit"
    assert lc["logical_match"] is True

