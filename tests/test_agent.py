"""Tests for agent prompts and runner (with mocked LLM)."""
from unittest.mock import patch

import pytest
from bola_ai.agent.prompts import build_analysis_prompt, BOLA_SYSTEM_PROMPT
from bola_ai.agent.runner import run_analysis, _normalize_report
from bola_ai.rag.store import DocStore


def test_system_prompt_contains_bola():
    assert "BOLA" in BOLA_SYSTEM_PROMPT
    assert "verification" in BOLA_SYSTEM_PROMPT.lower()


def test_build_analysis_prompt():
    prompt = build_analysis_prompt("Some API spec.", query="Find risks.")
    assert "Some API spec" in prompt
    assert "Find risks" in prompt


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
