"""
E2E tests: talk to the real LLM via the API and assert on report content (not just HTTP codes).

These tests verify that the LLM receives the ingested documentation and returns BOLA-focused
findings with verification steps. They require a running stack with Ollama and the bola-analyzer
model (e.g. docker compose up -d with model loaded).

Run with: PYTHONPATH=src pytest tests/test_e2e_llm.py -v -s
(requires live stack; see tests/conftest.py — collection fails if API/Ollama down unless BOLA_AI_SKIP_LIVE_E2E=1).

Fail if the report content does not match expectations.
"""
import os
from pathlib import Path

import httpx
import pytest

BASE_URL = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000").rstrip("/")
TIMEOUT_ANALYZE = 360.0  # match LLM + client policy (Issue 16)

# Path to sample project doc (used so LLM has concrete endpoints to analyze)
FIXTURE_DIR = Path(__file__).parent / "fixtures"
SAMPLE_DOC_PATH = FIXTURE_DIR / "sample_project_documentation.md"


@pytest.fixture(scope="module")
def sample_documentation():
    path = SAMPLE_DOC_PATH
    if not path.exists():
        pytest.skip(f"Fixture not found: {path}")
    return path.read_text(encoding="utf-8")


class TestE2ELLM:
    """
    E2E: ingest project docs, call analyze, assert on LLM report content.
    Proves the LLM is running and returns BOLA findings with verification steps.
    """

    @staticmethod
    def _reset_and_ingest(client: httpx.Client, sample_documentation: str, source: str) -> None:
        rr = client.post(f"{BASE_URL}/reset")
        assert rr.status_code == 200, rr.text
        ri = client.post(
            f"{BASE_URL}/ingest",
            data={"content": sample_documentation, "source": source},
        )
        assert ri.status_code == 200, ri.text

    def test_llm_report_references_ingested_documentation(self, sample_documentation):
        """Ingest sample project doc, analyze; report must reference our endpoints or resources."""
        with httpx.Client(timeout=TIMEOUT_ANALYZE) as client:
            self._reset_and_ingest(client, sample_documentation, "sample_project_documentation.md")

            r = client.post(
                f"{BASE_URL}/analyze",
                json={"query": "Identify BOLA risks and give verification steps for each finding."},
            )
            assert r.status_code == 200, r.text

        j = r.json()
        assert j.get("status") == "ok"
        report = j.get("report", "")

        # LLM must produce a substantial answer (not a one-liner or error)
        assert len(report) >= 200, f"Report too short (len={len(report)}); LLM may not have run."

        # Report should reference at least one resource/endpoint from our doc
        refs = ["patient", "order", "prescription", "case", "/api/"]
        found = [ref for ref in refs if ref.lower() in report.lower()]
        assert len(found) >= 1, f"Report should reference ingested doc (patient/order/prescription/case/api); got none. Report excerpt: {report[:500]}"

    def test_llm_report_contains_verification_steps(self, sample_documentation):
        """Report must contain verification steps (auditor-facing instructions)."""
        with httpx.Client(timeout=TIMEOUT_ANALYZE) as client:
            self._reset_and_ingest(client, sample_documentation, "e2e_fixture")
            r = client.post(
                f"{BASE_URL}/analyze",
                json={"query": "List potential BOLA issues and how to verify each one."},
            )
            assert r.status_code == 200, r.text

        report = (r.json().get("report") or "").lower()

        # Must mention verification or steps
        assert "verification" in report or "step" in report, (
            f"Report should include verification steps. Excerpt: {report[:600]}"
        )

        # Should look like instructions (call, request, token, etc.)
        instruction_words = ["call", "request", "token", "get ", "post ", "with two", "different user"]
        has_instruction = any(w in report for w in instruction_words)
        assert has_instruction, (
            f"Report should contain concrete verification instructions. Excerpt: {report[:600]}"
        )

    def test_llm_report_is_bola_focused(self, sample_documentation):
        """Report must contain BOLA-related security language."""
        with httpx.Client(timeout=TIMEOUT_ANALYZE) as client:
            self._reset_and_ingest(client, sample_documentation, "e2e_fixture")
            r = client.post(
                f"{BASE_URL}/analyze",
                json={"query": "What BOLA risks exist and how to verify them?"},
            )
            assert r.status_code == 200, r.text

        report = (r.json().get("report") or "").lower()

        bola_terms = ["bola", "ownership", "authorization", "access", "permission", "unauthorized"]
        found = [t for t in bola_terms if t in report]
        assert len(found) >= 2, (
            f"Report should be BOLA-focused (e.g. ownership, authorization). Found: {found}. Excerpt: {report[:500]}"
        )

    def test_llm_report_is_not_error_or_generic(self, sample_documentation):
        """Report must not be an error message or empty/generic placeholder."""
        with httpx.Client(timeout=TIMEOUT_ANALYZE) as client:
            self._reset_and_ingest(client, sample_documentation, "e2e_fixture")
            r = client.post(f"{BASE_URL}/analyze", json={})
            assert r.status_code == 200, r.text

        report = (r.json().get("report") or "").strip()

        assert len(report) >= 100, "Report too short."
        # Should not be primarily an error
        assert "404" not in report or "verification" in report
        assert "failed to load" not in report.lower() or len(report) > 300
        # Should have structure (headings or list)
        assert "##" in report or "###" in report or "- " in report or "**" in report
