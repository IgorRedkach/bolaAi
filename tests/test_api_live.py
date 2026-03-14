"""
Live API tests: hit a running API (e.g. docker compose up) and assert on responses.
Skip if API is not available (e.g. BOLA_AI_LIVE_URL unset and localhost:8000 not responding).
Run with: BOLA_AI_FAKE_EMBEDDER=1 PYTHONPATH=src pytest tests/test_api_live.py -v
Or against container: BOLA_AI_LIVE_URL=http://localhost:8000 pytest tests/test_api_live.py -v
"""
import os
import pytest
import httpx

BASE_URL = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000")
TIMEOUT = 120.0


def _api_available() -> bool:
    try:
        r = httpx.get(f"{BASE_URL.rstrip('/')}/health", timeout=5.0)
        return r.status_code == 200
    except Exception:
        return False


@pytest.mark.skipif(not _api_available(), reason="Live API not available at BOLA_AI_LIVE_URL / localhost:8000")
class TestLiveAPI:
    """Tests that run against a live API (container or uvicorn)."""

    def test_live_health(self):
        r = httpx.get(f"{BASE_URL.rstrip('/')}/health", timeout=10.0)
        assert r.status_code == 200
        j = r.json()
        assert j.get("status") == "ok"
        assert "documents_chunks" in j

    def test_live_ingest_then_analyze(self):
        # Ingest fake data
        r = httpx.post(
            f"{BASE_URL.rstrip('/')}/ingest",
            data={"content": "GET /api/users/{id}. No ownership check. GET /api/patients/{id}. No caller verification.", "source": "test_live"},
            timeout=30.0,
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert "chunks" in j or j.get("status") == "ok"

        # Analyze
        r = httpx.post(
            f"{BASE_URL.rstrip('/')}/analyze",
            json={"query": "Identify BOLA risks and suggest verification steps."},
            timeout=TIMEOUT,
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert j.get("status") == "ok"
        report = j.get("report", "")
        assert len(report) > 50
        # Should contain BOLA-related content
        assert "BOLA" in report or "ownership" in report.lower() or "verification" in report.lower()

    def test_live_ui(self):
        r = httpx.get(f"{BASE_URL.rstrip('/')}/", timeout=10.0)
        assert r.status_code == 200
        assert "BOLA" in r.text or "bola" in r.text.lower()
