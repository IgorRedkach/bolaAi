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


@patch("bola_ai.agent.runner.chat")
def test_analyze_after_ingest_uses_default_query_when_empty(mock_chat, api_client: TestClient):
    """Analyze endpoint should work with empty JSON by using its default query."""
    mock_chat.return_value = "## Potential BOLA\n- Default analyze query still returns a report."
    api_client.post("/ingest", data={"content": "API: GET /api/orders/{id}. No permission check.", "source": "test"})
    r = api_client.post("/analyze", json={})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j.get("status") == "ok"
    assert "report" in j and len(j["report"]) > 10
    mock_chat.assert_called_once()


def test_index_html(api_client: TestClient):
    r = api_client.get("/")
    assert r.status_code == 200
    assert "BOLA" in r.text or "bola" in r.text.lower()

# --- Chat endpoint tests ---

@pytest.fixture
def chat_client(tmp_path):
    """Create a test client with fake embedder for chat tests.

    Sets SHARED_DOCS_DIR to an empty temp dir so auto-ingest doesn't interfere.
    """
    from unittest.mock import patch
    from bola_ai.api import app as app_mod
    from bola_ai import config as cfg
    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"
    empty_shared = tmp_path / "empty_shared"
    empty_shared.mkdir()
    with patch.object(cfg, "USE_FAKE_EMBEDDER", True), \
         patch.object(cfg, "SHARED_DOCS_DIR", empty_shared):
        from bola_ai.api.app import create_app
        from fastapi.testclient import TestClient
        a = create_app()
        yield TestClient(a)
    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"


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


def test_store_add_document_batches_large_input(tmp_path):
    """DocStore.add_document batches ChromaDB adds to stay under max batch size."""
    from unittest.mock import MagicMock
    from bola_ai.rag.store import DocStore, CHROMA_MAX_BATCH
    from bola_ai.rag.fake_embedder import FakeEmbedder

    store = DocStore(
        persist_directory=tmp_path / "chroma",
        embedder=FakeEmbedder(),
    )
    big_doc = ("GET /api/v1/resource/{id}\nNo ownership check.\n\n") * 40000
    mock_coll = MagicMock()
    batch_sizes = []
    def track_add(**kw):
        batch_sizes.append(len(kw["ids"]))
    mock_coll.add = track_add
    store._collection = mock_coll

    chunk_ids = store.add_document(big_doc, source="big.md")
    assert len(chunk_ids) > CHROMA_MAX_BATCH, (
        f"Test doc should produce >{CHROMA_MAX_BATCH} chunks, got {len(chunk_ids)}"
    )
    assert len(batch_sizes) > 1, "Should have called add() multiple times"
    assert all(b <= CHROMA_MAX_BATCH for b in batch_sizes), (
        f"All batches should be <= {CHROMA_MAX_BATCH}, got {batch_sizes}"
    )


def test_store_add_document_succeeds_with_real_chroma(tmp_path):
    """DocStore.add_document works end-to-end with real ChromaDB for normal documents."""
    from bola_ai.rag.store import DocStore
    from bola_ai.rag.fake_embedder import FakeEmbedder

    store = DocStore(
        persist_directory=tmp_path / "chroma",
        embedder=FakeEmbedder(),
    )
    doc = ("GET /api/v1/resource/{id}\nNo ownership check.\n\n") * 500
    chunk_ids = store.add_document(doc, source="normal.md")
    assert len(chunk_ids) > 0
    assert store.count() == len(chunk_ids)


# --- Analysis guard: no user docs → block analysis ---

def test_chat_analysis_blocked_without_user_docs(chat_client):
    """Analysis should be refused when no user documents are ingested, even if store has RAG knowledge chunks."""
    r = chat_client.post("/api/chat", json={"message": "What BOLA risks exist?"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "info"
    assert "no documents" in data["content"].lower() or "not been ingested" in data["content"].lower()


def test_chat_analysis_allowed_after_ingest(chat_client, tmp_path):
    """Analysis proceeds after user ingests a document."""
    from unittest.mock import patch
    from bola_ai import config as cfg
    from bola_ai.api import app as app_mod

    doc_dir = tmp_path / "shared_for_ingest"
    doc_dir.mkdir()
    (doc_dir / "api.md").write_text("GET /api/v1/users/{userId}\nReturns user info. No ownership check.")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        r = chat_client.post("/api/chat", json={"message": "ingest api.md"})
    assert r.status_code == 200
    assert "ingested" in r.json()["content"].lower()

    assert app_mod.has_user_docs()

    with patch("bola_ai.agent.runner.chat") as mock_llm:
        mock_llm.return_value = "## BOLA Risk: GET /api/v1/users/{userId}"
        r = chat_client.post("/api/chat", json={"message": "What BOLA risks exist?"})
    assert r.status_code == 200
    assert r.json()["type"] == "analysis"


def test_chat_returns_info_when_startup_auto_analysis_running(chat_client):
    """If startup auto-analysis is running, chat returns quick info instead of long timeout."""
    from bola_ai.api import app as app_mod

    app_mod._auto_analysis_status = "analyzing"
    app_mod._user_doc_sources.add("doc.md")
    app_mod._user_doc_ingest_order.append("doc.md")
    r = chat_client.post("/api/chat", json={"message": "What BOLA risks exist?"})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "info"
    assert "startup auto-analysis is currently running" in data["content"].lower()


def test_chat_reset_clears_user_docs(chat_client, tmp_path):
    """After reset, user doc tracking is cleared and analysis is blocked again."""
    from unittest.mock import patch
    from bola_ai import config as cfg
    from bola_ai.api import app as app_mod

    doc_dir = tmp_path / "shared_for_reset"
    doc_dir.mkdir()
    (doc_dir / "api.md").write_text("GET /api/v1/orders/{id}")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        chat_client.post("/api/chat", json={"message": "ingest api.md"})
    assert app_mod.has_user_docs()

    chat_client.post("/api/chat", json={"message": "reset"})
    assert not app_mod.has_user_docs()

    r = chat_client.post("/api/chat", json={"message": "Analyze BOLA"})
    assert r.json()["type"] == "info"
    assert "no documents" in r.json()["content"].lower() or "not been ingested" in r.json()["content"].lower()


# --- Auto-ingest on startup ---

def test_auto_ingest_on_startup(tmp_path):
    """App auto-ingests files from shared docs on startup (background thread)."""
    import time
    from unittest.mock import patch
    from bola_ai.api import app as app_mod
    from bola_ai import config as cfg

    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"

    shared = tmp_path / "shared_auto"
    shared.mkdir()
    (shared / "net_log.md").write_text("GET /api/v1/accounts/{accountId}\nNo ownership check.")
    (shared / "har.md").write_text("POST /api/v1/transfers\nNo tenant filter.")

    with patch.object(cfg, "USE_FAKE_EMBEDDER", True), \
         patch.object(cfg, "SHARED_DOCS_DIR", shared):
        from bola_ai.api.app import create_app
        from fastapi.testclient import TestClient
        a = create_app()
        with TestClient(a) as client:
            for _ in range(60):
                if app_mod._auto_ingest_status == "done":
                    break
                time.sleep(0.5)

            assert app_mod._auto_ingest_status == "done", (
                f"Auto-ingest did not complete: {app_mod._auto_ingest_status}"
            )
            assert app_mod.has_user_docs()
            assert "net_log.md" in app_mod._user_doc_sources
            assert "har.md" in app_mod._user_doc_sources

            r = client.get("/health")
            assert r.json()["user_documents"] == 2
            assert r.json()["auto_ingest_status"] == "done"
            assert "auto_analysis_status" in r.json()

            r = client.get("/api/auto_analysis")
            assert r.status_code == 200
            assert "status" in r.json()

    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"


def test_auto_ingest_and_analyze_does_not_use_foreground_analysis_lock(tmp_path):
    """Startup auto-analysis should not call foreground serialized analysis helper."""
    from unittest.mock import patch
    from bola_ai.api import app as app_mod
    from bola_ai import config as cfg

    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"

    shared = tmp_path / "shared_auto_nonblocking"
    shared.mkdir()
    (shared / "doc.md").write_text("GET /api/v1/orders/{id}\nNo ownership check.", encoding="utf-8")

    with patch.object(cfg, "USE_FAKE_EMBEDDER", True), \
         patch.object(cfg, "SHARED_DOCS_DIR", shared), \
         patch.object(cfg, "AUTO_ANALYZE_ON_STARTUP", True), \
         patch.object(cfg, "AUTO_ANALYZE_TIMEOUT_SECONDS", 5.0), \
         patch.object(cfg, "AUTO_ANALYZE_N_CONTEXT", 4), \
         patch("bola_ai.agent.llm.is_available", return_value=True), \
         patch("bola_ai.api.app.analyze_for_bola", return_value="## Potential findings\n\n### Test finding"), \
         patch("bola_ai.api.app._run_serialized_analysis", side_effect=AssertionError("must not be called")):
        app_mod._auto_ingest_and_analyze()

    assert app_mod._auto_ingest_status == "done"
    assert app_mod._auto_analysis_status == "done"
    assert "Test finding" in (app_mod._auto_analysis_result or "")


def test_auto_ingest_and_analyze_limits_sources_for_startup_pass(tmp_path):
    """Startup auto-analysis should limit number of sources for responsiveness."""
    from unittest.mock import patch
    from bola_ai.api import app as app_mod
    from bola_ai import config as cfg

    app_mod._store = None
    app_mod._user_doc_sources.clear()
    app_mod._user_doc_ingest_order.clear()
    app_mod._auto_analysis_result = None
    app_mod._auto_analysis_status = "idle"

    shared = tmp_path / "shared_auto_limit"
    shared.mkdir()
    (shared / "a.md").write_text("GET /a/{id}\nNo ownership check.", encoding="utf-8")
    (shared / "b.md").write_text("GET /b/{id}\nNo ownership check.", encoding="utf-8")
    (shared / "c.md").write_text("GET /c/{id}\nNo ownership check.", encoding="utf-8")

    seen_filter = {}

    def _capture(*args, **kwargs):
        seen_filter["value"] = kwargs.get("source_filter") or []
        return "## Potential findings\n\n### Test"

    with patch.object(cfg, "USE_FAKE_EMBEDDER", True), \
         patch.object(cfg, "SHARED_DOCS_DIR", shared), \
         patch.object(cfg, "AUTO_ANALYZE_ON_STARTUP", True), \
         patch.object(cfg, "AUTO_ANALYZE_TIMEOUT_SECONDS", 5.0), \
         patch.object(cfg, "AUTO_ANALYZE_N_CONTEXT", 4), \
         patch.object(cfg, "AUTO_ANALYZE_MAX_SOURCES", 2), \
         patch("bola_ai.agent.llm.is_available", return_value=True), \
         patch("bola_ai.api.app.analyze_for_bola", side_effect=_capture):
        app_mod._auto_ingest_and_analyze()

    assert len(seen_filter["value"]) == 2
    assert seen_filter["value"] == ["b.md", "c.md"]

# --- Broader ingest phrases ---

@pytest.mark.parametrize("phrase", [
    "get the files",
    "get my documents",
    "investigate my files",
    "take a look at my documents",
    "scan the folder",
    "check my docs",
    "analyze my files",
    "read the documents",
    "look at my files",
    "process the docs",
    "load the files",
    "I placed my files in the folder",
    "I added documents to shared",
])
def test_chat_broad_ingest_phrases(chat_client, tmp_path, phrase):
    """Various natural language phrases should trigger bulk ingest."""
    from unittest.mock import patch
    from bola_ai import config as cfg

    doc_dir = tmp_path / "shared_phrases"
    doc_dir.mkdir(exist_ok=True)
    (doc_dir / "test.md").write_text("GET /api/v1/test/{id}\nNo auth check.")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        r = chat_client.post("/api/chat", json={"message": phrase})
    assert r.status_code == 200
    data = r.json()
    assert data["type"] == "info", f"Phrase '{phrase}' should trigger ingest but got type={data['type']}: {data['content'][:200]}"
    assert "test.md" in data["content"] or "1 file(s)" in data["content"], (
        f"Phrase '{phrase}' did not ingest: {data['content'][:200]}"
    )


# --- Health endpoint reports user docs ---

def test_health_shows_user_doc_count(chat_client, tmp_path):
    """Health endpoint should report user document count."""
    from unittest.mock import patch
    from bola_ai import config as cfg

    r = chat_client.get("/health")
    assert r.json()["user_documents"] == 0

    doc_dir = tmp_path / "shared_health"
    doc_dir.mkdir()
    (doc_dir / "doc.md").write_text("Some content.")

    with patch.object(cfg, "SHARED_DOCS_DIR", doc_dir):
        chat_client.post("/api/chat", json={"message": "ingest doc.md"})

    r = chat_client.get("/health")
    assert r.json()["user_documents"] == 1
    assert "doc.md" in r.json()["user_doc_sources"]

