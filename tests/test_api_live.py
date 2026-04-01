"""
Live E2E: hit a running API + Ollama (docker compose up). Mandatory when this file is collected.
See tests/conftest.py — start stack before pytest tests/.
"""
import os
import time

import httpx
import pytest

BASE_URL = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000")
TIMEOUT_ANALYZE = float(os.environ.get("BOLA_AI_ANALYZE_CLIENT_TIMEOUT", "1260"))


def _wait_for_startup_auto_analysis_to_settle(timeout_seconds: float = 300.0) -> None:
    """Wait until startup auto-analysis is no longer actively running.

    E2E reliability: if startup auto-analysis is still using the LLM, a concurrent
    test analyze call can be delayed or time out in constrained environments.
    """
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        r = httpx.get(f"{BASE_URL.rstrip('/')}/health", timeout=10.0)
        if r.status_code != 200:
            time.sleep(2)
            continue
        j = r.json()
        status = (j.get("auto_analysis_status") or "").lower()
        if status in ("idle", "done", "disabled") or status.startswith("error"):
            return
        time.sleep(2)
    pytest.fail("startup auto-analysis did not settle before live analyze test")


class TestLiveAPI:
    """Tests that run against a live API (container or uvicorn)."""

    def test_live_health(self):
        r = httpx.get(f"{BASE_URL.rstrip('/')}/health", timeout=10.0)
        assert r.status_code == 200
        j = r.json()
        assert j.get("status") == "ok"
        assert "documents_chunks" in j

    def test_live_ingest_then_analyze(self):
        _wait_for_startup_auto_analysis_to_settle()
        # Ingest fake data
        r = httpx.post(
            f"{BASE_URL.rstrip('/')}/ingest",
            data={"content": "GET /api/users/{id}. No ownership check. GET /api/patients/{id}. No caller verification.", "source": "test_live"},
            timeout=600.0,
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert "chunks" in j or j.get("status") == "ok"

        # Analyze
        # Keep live smoke query short and retry once if the model is cold/busy.
        r = None
        for attempt in range(2):
            try:
                r = httpx.post(
                    f"{BASE_URL.rstrip('/')}/analyze",
                    json={"query": "Identify one concrete BOLA risk from this document and give two-token verification."},
                    timeout=TIMEOUT_ANALYZE,
                )
            except httpx.ReadTimeout:
                if attempt == 0:
                    time.sleep(5)
                    continue
                raise
            if r.status_code == 200:
                break
            if r.status_code == 504 and attempt == 0:
                time.sleep(5)
                continue
            break
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
