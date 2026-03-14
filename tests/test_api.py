"""Tests for FastAPI endpoints (in-process TestClient, no real server)."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api_client(client: TestClient):
    return client


def test_health(api_client: TestClient):
    r = api_client.get("/health")
    assert r.status_code == 200
    j = r.json()
    assert "status" in j
    assert j["status"] == "ok"
    assert "documents_chunks" in j


def test_ingest_content(api_client: TestClient):
    r = api_client.post("/ingest", data={"content": "GET /api/users/123. No auth check.", "source": "test"})
    assert r.status_code == 200
    j = r.json()
    assert j.get("message") or "chunks" in str(j).lower() or "ok" in str(j).lower()


def test_ingest_missing(api_client: TestClient):
    r = api_client.post("/ingest", data={})
    assert r.status_code == 422 or r.status_code == 400  # validation or bad request


@patch("bola_ai.agent.runner.chat")
def test_analyze_after_ingest_mocked(mock_chat, api_client: TestClient):
    """Ingest then analyze via API; LLM mocked so we get deterministic 200 and can assert on report."""
    mock_chat.return_value = "## Potential BOLA\n- User API may not check ownership. Verification: call with two tokens."
    api_client.post("/ingest", data={"content": "API: GET /api/orders/{id}. Returns order. No permission check.", "source": "test"})
    r = api_client.post("/analyze", json={"query": "BOLA risks"})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("status") == "ok"
    assert "report" in j
    assert len(j["report"]) > 10
    mock_chat.assert_called_once()


def test_analyze_after_ingest(api_client: TestClient):
    """Ingest then analyze; if Ollama is available we get 200 and report, else 500."""
    api_client.post("/ingest", data={"content": "API: GET /api/orders/{id}. No permission check.", "source": "test"})
    r = api_client.post("/analyze", json={})
    assert r.status_code in (200, 500)
    if r.status_code == 200:
        j = r.json()
        assert "report" in j and j.get("status") == "ok"


def test_index_html(api_client: TestClient):
    r = api_client.get("/")
    assert r.status_code == 200
    assert "BOLA" in r.text or "bola" in r.text.lower()
