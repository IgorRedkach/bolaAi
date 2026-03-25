"""Tests for FastAPI endpoints (in-process TestClient, no real server)."""
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from bola_ai import config as app_config


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


def test_ingest_shared_success(api_client: TestClient, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    (shared / "doc.md").write_text("GET /api/v1/orders/{id}", encoding="utf-8")
    old = app_config.SHARED_DOCS_DIR
    app_config.SHARED_DOCS_DIR = shared
    try:
        r = api_client.post("/ingest_shared", data={"relative_path": "doc.md", "source": "shared-test"})
    finally:
        app_config.SHARED_DOCS_DIR = old
    assert r.status_code == 200, r.text
    assert "ingested" in r.json().get("message", "").lower()


def test_ingest_shared_blocks_path_traversal(api_client: TestClient, tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    outside = tmp_path / "outside.md"
    outside.write_text("GET /x", encoding="utf-8")
    old = app_config.SHARED_DOCS_DIR
    app_config.SHARED_DOCS_DIR = shared
    try:
        r = api_client.post("/ingest_shared", data={"relative_path": "../outside.md"})
    finally:
        app_config.SHARED_DOCS_DIR = old
    assert r.status_code == 400


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

# --- Chat endpoint tests ---

@pytest.fixture
def chat_client():
    """Create a test client with fake embedder for chat tests."""
    from unittest.mock import patch
    from bola_ai.api import app as app_mod
    from bola_ai import config as cfg
    app_mod._store = None
    with patch.object(cfg, "USE_FAKE_EMBEDDER", True):
        from bola_ai.api.app import create_app
        from fastapi.testclient import TestClient
        a = create_app()
        yield TestClient(a)
    app_mod._store = None


def test_chat_help_returns_usage_guide(chat_client):
    """Chat /api/chat with 'help' returns usage guide."""
    r = chat_client.post("/api/chat", json={"message": "help"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "help"
    assert "Usage Guide" in data["content"]
    assert "ingest" in data["content"].lower()


def test_chat_reset(chat_client):
    """Chat /api/chat with 'reset' clears store."""
    r = chat_client.post("/api/chat", json={"message": "reset"})
    assert r.status_code == 200
    data = r.json()
    assert "cleared" in data["content"].lower() or "reset" in data["content"].lower()


def test_chat_page_loads(chat_client):
    """GET /chat returns the chat HTML page."""
    r = chat_client.get("/chat")
    assert r.status_code == 200
    assert "BOLA AI" in r.text
    assert "chat" in r.text.lower()


def test_shared_docs_endpoint(chat_client):
    """GET /api/shared_docs returns file list."""
    r = chat_client.get("/api/shared_docs")
    assert r.status_code == 200
    data = r.json()
    assert "files" in data
    assert isinstance(data["files"], list)


def test_chat_bulk_ingest(chat_client, tmp_path):
    """Chat 'ingest' without filename ingests all files from shared_docs."""
    from unittest.mock import patch
    from bola_ai import config as cfg

    doc_dir = tmp_path / "shared"
    doc_dir.mkdir()
    (doc_dir / "api_spec.md").write_text("GET /api/v1/users/{id}\nNo ownership check.")
    (doc_dir / "schema.md").write_text("POST /api/v1/orders\nNo tenant filter.")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        r = chat_client.post("/api/chat", json={"message": "ingest"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "info"
    assert "2 file(s)" in data["content"]
    assert "api_spec.md" in data["content"]
    assert "schema.md" in data["content"]


def test_chat_bulk_ingest_ready_phrase(chat_client, tmp_path):
    """Chat 'documents are ready' triggers bulk ingest."""
    from unittest.mock import patch
    from bola_ai import config as cfg

    doc_dir = tmp_path / "shared"
    doc_dir.mkdir()
    (doc_dir / "test.md").write_text("Some API doc content here.")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        r = chat_client.post("/api/chat", json={"message": "documents are ready"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "info"
    assert "1 file(s)" in data["content"]
    assert "test.md" in data["content"]

