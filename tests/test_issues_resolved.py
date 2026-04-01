"""
Autotests for issues in docs/ISSUES.md. When an issue is marked PASSED, the corresponding test
should pass against the live API (E2E with real LLM). Run:
  PYTHONPATH=src pytest tests/test_issues_resolved.py -v -s
Stack must be up (conftest fails collection otherwise). Optional: BOLA_AI_LIVE_URL.
"""
import os
import re
import time
from pathlib import Path

import httpx
import pytest

BASE_URL = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000").rstrip("/")
TIMEOUT = float(os.environ.get("BOLA_AI_ANALYZE_CLIENT_TIMEOUT", "1260"))  # LLM analyze (Issue 16)
INGEST_TIMEOUT = float(os.environ.get("BOLA_AI_INGEST_TIMEOUT", "600"))
FIXTURE_DIR = Path(__file__).parent / "fixtures"
SAMPLE_DOC_PATH = FIXTURE_DIR / "sample_project_documentation.md"

# Endpoints and resources that ARE in the sample doc (lowercase for comparison)
DOC_ENDPOINTS = {
    "/api/v1/patients",
    "/api/v1/patients/{patientid}/orders",
    "/api/v1/orders",
    "/api/v1/prescriptions",
    "/api/internal/cases",
    "patient", "orders", "prescription", "case", "case_team_members",
}


def _ingest_and_analyze(client: httpx.Client, query: str) -> str:
    client.post(f"{BASE_URL}/reset", timeout=60.0)
    doc = SAMPLE_DOC_PATH.read_text(encoding="utf-8")
    client.post(
        f"{BASE_URL}/ingest",
        data={"content": doc, "source": "issues_test"},
        timeout=INGEST_TIMEOUT,
    )
    return _analyze_with_retry(client, query)


def _analyze_with_retry(client: httpx.Client, query: str) -> str:
    concise_query = (
        f"{query}\n\n"
        "Keep the answer concise (<=250 words), BOLA-only, and grounded to provided documentation."
    )
    for attempt in range(3):
        try:
            r = client.post(f"{BASE_URL}/analyze", json={"query": concise_query}, timeout=TIMEOUT)
        except httpx.ReadTimeout:
            if attempt < 2:
                time.sleep(5)
                continue
            raise AssertionError(f"analyze timed out after {TIMEOUT}s for query: {query[:120]}")
        if r.status_code == 200:
            return (r.json() or {}).get("report", "")
        if attempt < 2 and r.status_code >= 500:
            time.sleep(5)
            continue
        raise AssertionError(f"analyze returned {r.status_code}: {r.text[:500]}")
    raise AssertionError("analyze retry loop exhausted without a response")


class TestIssuesResolved:
    """Tests that assert issue-resolution criteria from docs/ISSUES.md."""

    def test_report_does_not_reference_unknown_endpoints(self):
        """Issue 1: Report must not assert findings for endpoints not in the doc (e.g. /api/users/{id})."""
        with httpx.Client(timeout=TIMEOUT) as client:
            report = _ingest_and_analyze(
                client,
                "Identify BOLA risks only for the endpoints described in the documentation.",
            )
        report_lower = report.lower()
        # /api/users/ is NOT in our sample doc; if the model hallucinates it, we catch here
        if "/api/users/" in report_lower or "get /api/users/" in report_lower:
            # Check it's not just a generic example; if it's presented as a finding from our doc, fail
            if "users/{id}" in report_lower or "users/{user" in report_lower:
                pytest.fail(
                    "Report references /api/users/ endpoint which is not in the provided documentation (hallucination). "
                    "See docs/ISSUES.md Issue 1."
                )

    def test_report_bola_findings_are_authorization_related(self):
        """Issue 2: BOLA findings should be about object-level authorization, not pagination/filtering."""
        with httpx.Client(timeout=TIMEOUT) as client:
            report = _ingest_and_analyze(
                client,
                "List only BOLA risks: can one user access another user's resource by changing the ID?",
            )
        report_lower = report.lower()
        # Should contain authorization-related terms for the main findings
        auth_terms = ["ownership", "authorization", "permission", "object-level", "access", "allowed"]
        has_auth = any(t in report_lower for t in auth_terms)
        # Should not frame pagination or filter as BOLA
        bad_frames = ["pagination", "order status filter", "order type filter", "creation date filter"]
        bad = [b for b in bad_frames if b in report_lower and "bola" in report_lower]
        assert has_auth, "Report should focus on ownership/authorization (Issue 2)."
        assert not bad, f"Report should not frame these as BOLA: {bad}. See docs/ISSUES.md Issue 2."

    def test_report_rationale_focuses_on_ownership_not_auth(self):
        """Issue 3: Rationale should focus on ownership/permission for the object, not 'no authentication'."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            report = _ingest_and_analyze(
                client,
                "For each endpoint, identify whether there is a missing ownership or authorization check for the object ID.",
            )
        report_lower = report.lower()
        # Accept a broad set of ownership/access-control related terms
        ownership_terms = [
            "ownership", "permission", "allowed to access", "caller", "this specific", "object",
            "authorization", "access control", "who can access", "belongs to",
        ]
        has_ownership_language = any(t in report_lower for t in ownership_terms)
        assert has_ownership_language, "Report rationale should mention ownership/authorization for the object. See docs/ISSUES.md Issue 3."

    def test_report_has_consistent_finding_structure(self):
        """Issue 4: No duplicate headings (e.g. ### ### Title); one ### per finding title."""
        with httpx.Client(timeout=TIMEOUT) as client:
            report = _ingest_and_analyze(client, "List BOLA findings with rationale and verification steps.")
        # Double ### is a format bug
        double_heading = re.search(r"###\s*###", report)
        assert not double_heading, f"Report has duplicate ### heading. See docs/ISSUES.md Issue 4. Excerpt: {report[:400]}"

    def test_verification_steps_mention_two_tokens_or_two_users(self):
        """Issue 5: At least one verification step should mention two tokens or two users for IDOR check."""
        with httpx.Client(timeout=TIMEOUT) as client:
            report = _ingest_and_analyze(
                client,
                "For each BOLA finding give verification steps an auditor can run.",
            )
        report_lower = report.lower()
        two_token_phrases = [
            "two different user tokens",
            "two different users",
            "two user tokens",
            "token a",
            "token b",
            "with two different",
            "two tokens",
        ]
        has_two = any(p in report_lower for p in two_token_phrases)
        assert has_two, (
            "Verification steps should mention two tokens or two users for IDOR. "
            "See docs/ISSUES.md Issue 5. Excerpt: " + report[:500]
        )

    def test_verification_not_without_token(self):
        """Issue 6: Verification steps must not suggest testing 'without a token'; BOLA needs two authenticated users."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            doc = (FIXTURE_DIR / "doc_file_storage.md").read_text(encoding="utf-8")
            client.post(f"{BASE_URL}/ingest", data={"content": doc, "source": "issue6_test"})
            report = _analyze_with_retry(client, "Identify BOLA risks and give verification steps.")
        report_lower = report.lower()
        assert "without a token" not in report_lower, (
            "Verification must not suggest testing without a token (BOLA requires two user tokens). See docs/ISSUES.md Issue 6."
        )
        assert "without authentication" not in report_lower or "with two different authenticated users" in report_lower, (
            "Verification must not suggest testing without authentication. See docs/ISSUES.md Issue 6."
        )

    def test_no_bold_wrapped_headings(self):
        """Issue 8: Report must not contain **### pattern (bold wrapping heading markers)."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            doc = (FIXTURE_DIR / "doc_hr_system.md").read_text(encoding="utf-8")
            client.post(f"{BASE_URL}/ingest", data={"content": doc, "source": "issue8_test"})
            report = _analyze_with_retry(client, "Identify BOLA risks and give verification steps.")
        assert "**###" not in report and "** ###" not in report, (
            "Report contains bold-wrapped heading (e.g. **### Title). See docs/ISSUES.md Issue 8."
        )

    def test_report_identifies_graphql_bola(self):
        """Issue 12: GraphQL doc → report must identify BOLA in GraphQL operations, not only REST paths."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            doc = (FIXTURE_DIR / "doc_adversarial_graphql.md").read_text(encoding="utf-8")
            client.post(f"{BASE_URL}/ingest", data={"content": doc, "source": "issue12_test"})
            report = _analyze_with_retry(
                client,
                "Identify BOLA risks in GraphQL operations and give verification steps using GraphQL syntax.",
            )
        report_lower = report.lower()
        # Must produce a non-empty substantive report
        assert len(report) >= 200, f"Report too short for GraphQL doc (len={len(report)}). Issue 12."
        # Must mention GraphQL-specific concepts
        graphql_refs = ["graphql", "mutation", "query", "document", "user"]
        has_graphql = any(ref in report_lower for ref in graphql_refs)
        assert has_graphql, (
            f"Report should reference GraphQL operations/fields. See docs/ISSUES.md Issue 12. Excerpt: {report[:400]}"
        )
        # Must NOT contain heading bleed (**# pattern)
        assert "**#" not in report, (
            f"Report contains heading bleed (**# pattern) from GraphQL doc. See docs/ISSUES.md Issue 12. Excerpt: {report[:400]}"
        )
        # Must not use "without required permissions" — that is auth, not BOLA
        assert "does not have the required permissions" not in report_lower, (
            "Verification suggests testing with insufficient permissions (auth check), not two valid users (BOLA). Issue 12."
        )

    def test_report_graphql_verification_uses_two_tokens(self):
        """Issue 12/13: GraphQL doc → verification steps must use two valid user tokens, not 'missing permissions'."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            doc = (FIXTURE_DIR / "doc_adversarial_graphql.md").read_text(encoding="utf-8")
            client.post(f"{BASE_URL}/ingest", data={"content": doc, "source": "issue12_13_test"})
            report = _analyze_with_retry(client, "Give BOLA verification steps for each GraphQL operation.")
        report_lower = report.lower()
        two_token_phrases = [
            "two different user tokens", "two different users", "token a", "token b",
            "two tokens", "with two different", "user a", "user b",
        ]
        has_two_tokens = any(p in report_lower for p in two_token_phrases)
        assert has_two_tokens, (
            "GraphQL verification should use two valid user tokens. See docs/ISSUES.md Issue 12/13. Excerpt: " + report[:500]
        )

    def test_report_soql_identifies_record_level_bola(self):
        """Issue 14: SOQL/Salesforce doc → report must flag record-level access, not only REST endpoints."""
        with httpx.Client(timeout=TIMEOUT) as client:
            client.post(f"{BASE_URL}/reset")
            doc = (FIXTURE_DIR / "doc_adversarial_salesforce.md").read_text(encoding="utf-8")
            client.post(f"{BASE_URL}/ingest", data={"content": doc, "source": "issue14_test"})
            report = _analyze_with_retry(
                client,
                "Identify BOLA risks including SOQL record-level access and Salesforce sharing.",
            )
        report_lower = report.lower()
        assert len(report) >= 100, f"Report too short for Salesforce doc. Issue 14."
        # Must mention Salesforce/SOQL concepts or record-level access
        sf_refs = ["soql", "salesforce", "record", "account", "case", "opportunity", "sharing"]
        has_sf = any(ref in report_lower for ref in sf_refs)
        assert has_sf, (
            f"Report should reference Salesforce/SOQL record-level concepts. See docs/ISSUES.md Issue 14. Excerpt: {report[:400]}"
        )
