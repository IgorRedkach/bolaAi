"""
Live E2E: hit a running API + Ollama (docker compose up). Mandatory when this file is collected.
See tests/conftest.py — start stack before pytest tests/.
"""
import os

import httpx
import pytest

BASE_URL = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000")
TIMEOUT_ANALYZE = 360.0


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
            timeout=600.0,
        )
        assert r.status_code == 200, r.text
        j = r.json()
        assert "chunks" in j or j.get("status") == "ok"

        # Analyze
        r = httpx.post(
            f"{BASE_URL.rstrip('/')}/analyze",
            json={"query": "Identify BOLA risks and suggest verification steps."},
            timeout=TIMEOUT_ANALYZE,
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
