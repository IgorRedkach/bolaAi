"""Regressions for agent E2E-loop-specific failures.

These tests focus on strict q5/q6 output-shape requirements from adaptive loops.
"""

from bola_ai.agent.runner import _normalize_report


def test_e2e_loop_issue_35_q5_returns_only_two_curl_commands():
    raw = (
        "## Potential findings\n"
        "### Drifted output\n"
        "Model returned narrative instead of strict curls."
    )
    out = _normalize_report(
        raw,
        allowed_paths=["/graphql"],
        context="POST /graphql",
        user_query=(
            "Give **only** two curl commands—Alice then Bob—same URL path and same HTTP method as in the doc."
        ),
    )
    lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(lines) == 2
    assert lines[0].startswith("curl -X POST")
    assert "token_A" in lines[0]
    assert "token_B" in lines[1]


def test_e2e_loop_issue_36_q6_returns_path_audit_only():
    raw = (
        "## Potential findings\n"
        "### GET /api/v1/vendors/{vendorId}/bids/{bidId}\n"
        "**Rationale:** drifted q6 body.\n"
    )
    out = _normalize_report(
        raw,
        allowed_paths=["/api/v1/vendors/{vendorId}/bids/{bidId}"],
        context="GET /api/v1/vendors/{vendorId}/bids/{bidId}",
        user_query=(
            "Review your previous answer and state YES if it appears in the ingested documentation text or NO if hallucinated."
        ),
    )
    assert out.startswith("## Path Audit")
    assert "-> YES" in out
    assert "Potential findings" not in out
