"""FastAPI app: ingest, analyze, health."""

import logging
from pathlib import Path
from typing import Optional

import httpx as _httpx
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

    @app.post("/ingest_shared")
    def ingest_shared(
        relative_path: str = Form(...),
        source: str = Form("shared_volume"),
    ):
        """Ingest UTF-8 text file from shared docs volume path."""
        if not relative_path or not relative_path.strip():
            raise HTTPException(400, "Provide 'relative_path'.")
        store = get_store()
        shared_root = app_config.SHARED_DOCS_DIR.resolve()
        target = (shared_root / relative_path).resolve()
        try:
            target.relative_to(shared_root)
        except ValueError:
            raise HTTPException(400, "relative_path must stay under shared docs directory.")
        if not target.is_file():
            raise HTTPException(404, f"Shared file not found: {relative_path}")
        try:
            text = target.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "Shared file must be UTF-8 text.")
        logger.info("Ingest shared: path=%s size=%s", target, len(text))
        store.add_document(text, source=source or target.name)
        n = store.count()
        logger.info("Ingest shared done: total chunks=%s", n)
        log_memory(logger, "after ingest (shared)")
        return {
            "status": "ok",
            "message": f"Shared file {relative_path} ingested",
            "chunks": n,
            "shared_docs_dir": str(shared_root),
        }

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
        except _httpx.TimeoutException as e:
            logger.error("Analyze timed out (LLM inference): %s", e)
            raise HTTPException(
                504,
                "LLM inference timed out. The model did not respond within the allowed "
                "time. Simplify your query or wait for the model to free up.",
            )
        except Exception as e:
            logger.exception("Analyze failed: %s", e)
            raise HTTPException(500, str(e))

    # --- Shared docs listing ---
    @app.get("/api/shared_docs")
    def list_shared_docs():
        """List files in the shared docs directory."""
        shared_root = app_config.SHARED_DOCS_DIR.resolve()
        if not shared_root.exists():
            return {"files": [], "shared_docs_dir": str(shared_root)}
        files = []
        for f in sorted(shared_root.iterdir()):
            if f.is_file() and not f.name.startswith("."):
                files.append({"name": f.name, "size": f.stat().st_size})
        return {"files": files, "shared_docs_dir": str(shared_root)}

    # --- Chat endpoint with smart routing ---
    class ChatRequest(BaseModel):
        message: str

    USAGE_GUIDE = """## BOLA AI — Usage Guide

**I'm a local, offline BOLA (Broken Object-Level Authorization) analysis tool.** Here's how to talk to me:

### Getting Started
1. **Copy your API documentation** (markdown, text, HAR analysis) into the `shared_docs/` folder
2. **Tell me to ingest:** Type `ingest` to load all files, or `ingest <filename>` for a specific one
3. **Ask me questions:** "What BOLA risks exist?" or "Generate curl commands to test BOLA on GET /api/users/{id}"

### Commands I Understand
| What you say | What I do |
|---|---|
| `help` or `how do I use this?` | Show this guide |
| `ingest <filename>` | Ingest a specific file from `shared_docs/` |
| `ingest` or `documents are ready` | Ingest **all** files from `shared_docs/` at once |
| `list files` or `what files are available?` | List files in `shared_docs/` |
| `status` | Show system health and chunk count |
| `reset` | Clear all ingested documents |
| Any BOLA/security question | Run analysis on ingested docs |

### Example Conversation
```
You: documents are ready
Bot: ✓ Ingested 3 files (24 chunks total)

You: ingest my-api-spec.md
Bot: ✓ Ingested my-api-spec.md (12 chunks)

You: What BOLA vulnerabilities exist in this API?
Bot: ## Potential findings ...

You: Generate curl commands to test BOLA on GET /users/{id} with two tokens
Bot: ## Verification steps ...
```

### Tips
- **Analysis takes 1-4 minutes** (local LLM, no internet needed)
- **Ingest multiple docs** before analyzing for richer context
- **Ask follow-up questions** — context is retained until you reset
- **Shared docs folder** is `shared_docs/` in the project directory
- Say `ingest` (no filename) or "documents are ready" to **ingest all files at once**
"""

    @app.post("/api/chat")
    def chat(body: ChatRequest):
        """Smart chat endpoint: routes messages to appropriate handlers."""
        msg = body.message.strip()
        msg_lower = msg.lower()
        logger.info("Chat message: %s", msg[:100])

        # Help / usage guidance
        if any(kw in msg_lower for kw in ("help", "how do i use", "how to use", "guide", "what can you do", "usage")):
            return {"role": "assistant", "content": USAGE_GUIDE, "type": "help"}

        # Status
        if msg_lower in ("status", "health", "info"):
            from bola_ai.agent.llm import is_available
            store = get_store()
            ollama_ok = is_available()
            return {
                "role": "assistant",
                "content": f"**System status:**\n- Ollama: {'online' if ollama_ok else 'offline'}\n- Ingested chunks: {store.count()}\n- Shared docs folder: `shared_docs/` (in your project directory)",
                "type": "info",
            }

        # Reset
        if msg_lower in ("reset", "clear", "start over"):
            store = get_store()
            store.reset()
            return {"role": "assistant", "content": "Document store cleared. You can now ingest new documents.", "type": "info"}

        # List files
        if any(kw in msg_lower for kw in ("list files", "what files", "available files", "show files", "shared docs", "what documents")):
            shared_root = app_config.SHARED_DOCS_DIR.resolve()
            if not shared_root.exists():
                return {"role": "assistant", "content": f"Shared docs directory not found: {shared_root}", "type": "error"}
            files = [f.name for f in sorted(shared_root.iterdir()) if f.is_file() and not f.name.startswith(".")]
            if not files:
                return {"role": "assistant", "content": "No files found. Copy your API docs into `shared_docs/` in the project folder and try again.", "type": "info"}
            file_list = "\n".join(f"- `{f}`" for f in files)
            return {
                "role": "assistant",
                "content": f"**Files in `shared_docs/` ({len(files)}):**\n{file_list}\n\nSay `ingest` to load all, or `ingest <filename>` for one.",
                "type": "info",
            }

        # Ingest command — single file or bulk
        import re as _re

        # Check for bare "ingest" / "ready" / "documents are ready" → bulk ingest all
        _bulk_triggers = (
            "ingest", "ingest all", "load all", "import all",
            "documents are ready", "docs are ready", "files are ready",
            "ready to ingest", "ready to analyze", "i copied the documents",
            "i copied the files", "i put the files", "all files",
        )
        is_bulk = msg_lower.strip() in _bulk_triggers or _re.search(
            r"\b(?:ready|copied|put|placed|added)\b.*\b(?:documents?|files?|docs?)\b",
            msg_lower,
        )

        # Check for single-file ingest
        ingest_match = _re.match(
            r"(?:ingest|load|import|read|add)\s+[\"\'`]?([\w.\-]+\.\w+)[\"\'`]?",
            msg_lower,
        )
        if not ingest_match:
            ingest_match = _re.search(
                r"(?:copied|added|put|placed)\s+[\"\'`]?([\w.\-]+\.\w+)[\"\'`]?",
                msg_lower,
            )

        if ingest_match:
            filename = ingest_match.group(1)
            shared_root = app_config.SHARED_DOCS_DIR.resolve()
            target = (shared_root / filename).resolve()
            try:
                target.relative_to(shared_root)
            except ValueError:
                return {"role": "assistant", "content": f"Invalid path: {filename}", "type": "error"}
            if not target.is_file():
                files = [f.name for f in sorted(shared_root.iterdir()) if f.is_file() and not f.name.startswith(".")]
                suggestion = "\n".join(f"- `{f}`" for f in files[:10]) if files else "(none)"
                return {
                    "role": "assistant",
                    "content": f"File not found: `{filename}`\n\n**Available files in `shared_docs/`:**\n{suggestion}",
                    "type": "error",
                }
            try:
                text = target.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                return {"role": "assistant", "content": f"File `{filename}` is not valid UTF-8 text.", "type": "error"}
            store = get_store()
            store.add_document(text, source=filename)
            n = store.count()
            return {
                "role": "assistant",
                "content": f"Ingested **{filename}** ({len(text):,} chars, {n} total chunks).\n\nYou can now ask me about BOLA risks in this document.",
                "type": "info",
            }

        if is_bulk:
            shared_root = app_config.SHARED_DOCS_DIR.resolve()
            if not shared_root.exists():
                return {"role": "assistant", "content": "Shared docs directory not found. Make sure `shared_docs/` exists in the project folder.", "type": "error"}
            files = [f for f in sorted(shared_root.iterdir()) if f.is_file() and not f.name.startswith(".")]
            if not files:
                return {"role": "assistant", "content": "No files found in `shared_docs/`. Copy your API documentation there first.", "type": "info"}
            store = get_store()
            ingested = []
            errors = []
            for f in files:
                try:
                    text = f.read_text(encoding="utf-8")
                    store.add_document(text, source=f.name)
                    ingested.append(f"- **{f.name}** ({len(text):,} chars)")
                except UnicodeDecodeError:
                    errors.append(f"- `{f.name}` (skipped — not UTF-8)")
            n = store.count()
            parts = [f"Ingested **{len(ingested)} file(s)** from `shared_docs/` ({n} total chunks):\n"]
            parts.append("\n".join(ingested))
            if errors:
                parts.append("\n\n**Skipped:**\n" + "\n".join(errors))
            parts.append("\n\nYou can now ask me about BOLA risks in these documents.")
            return {"role": "assistant", "content": "".join(parts), "type": "info"}

        # Default: BOLA analysis
        store = get_store()
        if store.count() == 0:
            return {
                "role": "assistant",
                "content": "No documents ingested yet. Please ingest first:\n- Copy files into `shared_docs/` in your project folder\n- Then say `ingest` to load all, or `ingest <filename>` for one\n\nType `help` for full usage guide.",
                "type": "info",
            }
        try:
            result = analyze_for_bola(store, custom_query=msg)
            return {"role": "assistant", "content": result, "type": "analysis"}
        except _httpx.TimeoutException:
            return {
                "role": "assistant",
                "content": "The analysis timed out. The LLM did not respond in time. Try a simpler question or wait a moment.",
                "type": "error",
            }
        except Exception as e:
            logger.exception("Chat analyze failed: %s", e)
            return {"role": "assistant", "content": f"Error: {e}", "type": "error"}

    @app.get("/", response_class=HTMLResponse)
    def index():
        """Minimal UI: ingest text and run analysis."""
        return _index_html()

    @app.get("/chat", response_class=HTMLResponse)
    def chat_ui():
        """Interactive chat UI."""
        return _chat_html()

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


def _chat_html() -> str:
    html = Path(__file__).parent / "chat.html"
    if html.exists():
        return html.read_text(encoding="utf-8")
    return "<html><body><h1>BOLA AI Chat</h1><p>chat.html not found</p></body></html>"
