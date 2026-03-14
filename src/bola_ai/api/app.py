"""FastAPI app: ingest, analyze, health."""

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from bola_ai.logging_config import get_logger

logger = get_logger("api")
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from bola_ai.agent.runner import analyze_for_bola, run_analysis
from bola_ai import config as app_config
from bola_ai.logging_config import setup_logging
from bola_ai.memory import log_memory
from bola_ai.rag.store import DocStore

# Lazy singleton store
_store: Optional[DocStore] = None


def get_store() -> DocStore:
    global _store
    if _store is None:
        logger.info("Initializing RAG store at %s", app_config.CHROMA_PATH)
        from bola_ai.rag.fake_embedder import FakeEmbedder
        kwargs = {
            "persist_directory": app_config.CHROMA_PATH,
            "collection_name": app_config.COLLECTION_NAME,
        }
        if getattr(app_config, "USE_FAKE_EMBEDDER", False):
            kwargs["embedder"] = FakeEmbedder()
            logger.info("Using fake embedder (low-memory mode)")
        else:
            kwargs["embedding_model"] = app_config.EMBEDDING_MODEL
        _store = DocStore(**kwargs)
        logger.info("RAG store ready; chunks=%s", _store.count())
        log_memory(logger, "after get_store init")
    return _store


def create_app() -> FastAPI:
    setup_logging(level=getattr(app_config, "LOG_LEVEL", "INFO"))
    log_memory(logger, "create_app start")
    app = FastAPI(
        title="BOLA AI",
        description="Local AI agent for BOLA (Broken Object-Level Authorization) analysis",
        version="0.1.0",
    )

    @app.get("/health")
    def health():
        from bola_ai.agent.llm import is_available
        ollama_ok = is_available()
        store = get_store()
        logger.info("Health check: ollama=%s chunks=%s", ollama_ok, store.count())
        return {
            "status": "ok",
            "ollama": ollama_ok,
            "documents_chunks": store.count(),
        }

    @app.post("/reset")
    def reset_store():
        """Clear the document store (for testing: ensures each test case runs with only the ingested doc)."""
        store = get_store()
        store.reset()
        return {"status": "ok", "message": "Store reset", "chunks": store.count()}

    @app.post("/ingest")
    def ingest(
        content: Optional[str] = Form(None),
        file: Optional[UploadFile] = File(None),
        source: str = Form("upload"),
    ):
        """Ingest text: either raw content or file upload."""
        store = get_store()
        if content:
            logger.info("Ingest: content length=%s source=%s", len(content or ""), source)
            store.add_document(content, source=source)
            n = store.count()
            logger.info("Ingest done: total chunks=%s", n)
            log_memory(logger, "after ingest (content)")
            return {"status": "ok", "message": "Content ingested", "chunks": n}
        if file:
            raw = file.file.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                logger.warning("Ingest: file %s not UTF-8", file.filename)
                raise HTTPException(400, "File must be UTF-8 text.")
            logger.info("Ingest: file=%s size=%s", file.filename, len(text))
            store.add_document(text, source=file.filename or "upload")
            n = store.count()
            logger.info("Ingest done: total chunks=%s", n)
            log_memory(logger, "after ingest (file)")
            return {"status": "ok", "message": f"File {file.filename} ingested", "chunks": n}
        logger.warning("Ingest: missing content and file")
        raise HTTPException(400, "Provide either 'content' or 'file'.")

    class AnalyzeRequest(BaseModel):
        query: Optional[str] = None

    @app.post("/analyze")
    def analyze(body: Optional[AnalyzeRequest] = None):
        """Run BOLA analysis on ingested docs. Optional custom query."""
        store = get_store()
        query = body.query if body and body.query else None
        logger.info("Analyze: query=%s chunks_available=%s", query or "(default)", store.count())
        try:
            result = analyze_for_bola(store, custom_query=query)
            logger.info("Analyze: completed report_len=%s", len(result or ""))
            log_memory(logger, "after analyze")
            return {"status": "ok", "report": result}
        except Exception as e:
            logger.exception("Analyze failed: %s", e)
            raise HTTPException(500, str(e))

    @app.get("/", response_class=HTMLResponse)
    def index():
        """Minimal UI: ingest text and run analysis."""
        return _index_html()

    return app


def _index_html() -> str:
    html = Path(__file__).parent / "index.html"
    if html.exists():
        return html.read_text(encoding="utf-8")
    return """
    <!DOCTYPE html>
    <html>
    <head><title>BOLA AI</title></head>
    <body>
    <h1>BOLA AI</h1>
    <p>Local BOLA analysis. Use API: POST /ingest, POST /analyze.</p>
    </body>
    </html>
    """
