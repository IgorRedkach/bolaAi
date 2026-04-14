"""FastAPI app: ingest, analyze, health."""

import logging
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional
import re

import httpx as _httpx
from fastapi import FastAPI, File, Form, HTTPException, UploadFile

from bola_ai.logging_config import get_logger

logger = get_logger("api")
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from bola_ai.agent.runner import analyze_for_bola, run_analysis, is_fast_path_query
from bola_ai import config as app_config
from bola_ai.logging_config import setup_logging
from bola_ai.memory import log_memory
from bola_ai.rag.store import DocStore

# Lazy singleton store (thread-safe)
_store: Optional[DocStore] = None
_store_lock = threading.Lock()
_store_ops_lock = threading.Lock()
_analysis_lock = threading.Lock()
_user_doc_sources: set[str] = set()
_user_doc_ingest_order: list[str] = []


def get_store() -> DocStore:
    global _store
    if _store is not None:
        return _store
    with _store_lock:
        if _store is not None:
            return _store
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


def has_user_docs() -> bool:
    return len(_user_doc_sources) > 0


def _track_user_doc(source: str) -> None:
    _user_doc_sources.add(source)
    if source not in _user_doc_ingest_order:
        _user_doc_ingest_order.append(source)


def _safe_add_document(store: DocStore, text: str, *, source: str, attempts: int = 3) -> None:
    """Add a document with short retries for transient Chroma/SQLite contention."""
    last_err: Exception | None = None
    for i in range(1, attempts + 1):
        try:
            with _store_ops_lock:
                store.add_document(text, source=source)
            return
        except Exception as exc:
            last_err = exc
            msg = str(exc).lower()
            retryable = (
                ("database is locked" in msg)
                or ("sqlite" in msg)
                or ("timeout" in msg)
                or ("does not exist" in msg and "collection" in msg)
            )
            if i < attempts and retryable:
                wait_s = 0.2 * i
                logger.warning(
                    "Ingest retry (%s/%s) for source=%s due to transient store error: %s",
                    i, attempts, source, exc,
                )
                if "does not exist" in msg and "collection" in msg:
                    with _store_ops_lock:
                        try:
                            store.reset()
                        except Exception as reset_exc:
                            logger.warning("Store reset during retry failed: %s", reset_exc)
                time.sleep(wait_s)
                continue
            raise
    if last_err:
        raise last_err


def _run_serialized_analysis(
    store: DocStore,
    *,
    query: Optional[str],
    source_filter: Optional[list[str]],
    timeout: Optional[float] = None,
    caller: str = "api",
) -> str:
    """Serialize LLM analyze calls to avoid contention timeouts.

    Running multiple heavy analysis requests concurrently can severely degrade
    throughput and cause avoidable timeouts. We run one analyze at a time.
    """
    logger.info("Analyze lock: waiting (caller=%s)", caller)
    with _analysis_lock:
        logger.info("Analyze lock: acquired (caller=%s)", caller)
        return analyze_for_bola(
            store,
            custom_query=query,
            source_filter=source_filter,
            timeout=timeout,
        )


def _finalize_analysis_output(report: str, query: str) -> str:
    """Final safety pass on analysis output before returning to clients."""
    out = report or ""

    # Remove any placeholder marker variants that reduce actionable quality.
    out = out.replace("[use only endpoints from documentation]", "")
    out = re.sub(r"\[[^\]]*endpoints[^\]]*documentation[^\]]*\]", "", out, flags=re.I)

    q = (query or "").lower()
    wants_comparative = (
        ("two token" in q)
        or ("two-token" in q)
        or ("same object path" in q)
        or ("comparative verification" in q)
    )
    low = out.lower()
    has_pair = (
        ("auth_token_1" in low and "auth_token_2" in low)
        or ("principal 1" in low and "principal 2" in low)
        or ("user a" in low and "user b" in low)
    )
    has_curl = "curl" in low
    if wants_comparative and (not has_pair or not has_curl):
        out = out.rstrip() + (
            "\n\n## Comparative Verification (API finalizer)\n"
            "```bash\n"
            "curl -i -X GET \"https://api.example.com/api/v1/resource/{id}\" \\\n"
            "  -H \"Authorization: Bearer AUTH_TOKEN_1\" \\\n"
            "  -H \"Content-Type: application/json\"\n"
            "```\n\n"
            "```bash\n"
            "curl -i -X GET \"https://api.example.com/api/v1/resource/{id}\" \\\n"
            "  -H \"Authorization: Bearer AUTH_TOKEN_2\" \\\n"
            "  -H \"Content-Type: application/json\"\n"
            "```\n"
        )
    return out.strip()


_auto_ingest_status: str = "idle"
_auto_analysis_status: str = "idle"
_auto_analysis_result: Optional[str] = None
_AUTO_ANALYZE_QUERY = (
    "Analyze only uploaded user documents for likely security vulnerabilities. "
    "Prioritize object-level authorization findings when evidenced, and return up to 3 highest-confidence, source-grounded findings with exact endpoints and concise class-appropriate verification steps."
)


def _auto_ingest_and_analyze():
    """Auto-ingest files from shared docs, then auto-analyze (runs in background thread)."""
    global _auto_ingest_status, _auto_analysis_status, _auto_analysis_result
    shared_root = app_config.SHARED_DOCS_DIR.resolve()
    if not shared_root.exists():
        logger.info("Auto-ingest: shared docs dir not found (%s)", shared_root)
        _auto_ingest_status = "done"
        return
    files = [f for f in sorted(shared_root.iterdir()) if f.is_file() and not f.name.startswith(".")]
    if not files:
        logger.info("Auto-ingest: no files in shared docs")
        _auto_ingest_status = "done"
        return
    _auto_ingest_status = f"ingesting {len(files)} file(s)..."
    logger.info("Auto-ingest: found %d file(s) in shared docs, ingesting...", len(files))
    try:
        store = get_store()
    except Exception as e:
        logger.error("Auto-ingest: failed to initialize store: %s", e)
        _auto_ingest_status = f"error: {e}"
        return
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
            _safe_add_document(store, text, source=f.name)
            _track_user_doc(f.name)
            logger.info("Auto-ingest: %s (%d chars)", f.name, len(text))
        except UnicodeDecodeError:
            logger.warning("Auto-ingest: skipped %s (not UTF-8)", f.name)
        except Exception as e:
            logger.warning("Auto-ingest: failed %s: %s", f.name, e)
    _auto_ingest_status = "done"
    logger.info("Auto-ingest: done. User docs: %s, total chunks: %d",
                 list(_user_doc_sources), store.count())

    if not has_user_docs():
        logger.info("Auto-analyze: no user docs ingested, skipping")
        return
    if not app_config.AUTO_ANALYZE_ON_STARTUP:
        logger.info("Auto-analyze: disabled by config")
        _auto_analysis_status = "disabled"
        return

    # Wait for Ollama to be ready before analyzing
    from bola_ai.agent.llm import is_available
    import time
    _auto_analysis_status = "waiting_for_ollama"
    logger.info("Auto-analyze: waiting for Ollama...")
    for _ in range(120):
        if is_available():
            break
        time.sleep(2)
    else:
        logger.error("Auto-analyze: Ollama not available after 240s, skipping analysis")
        _auto_analysis_status = "error: ollama_unavailable"
        return

    _auto_analysis_status = "analyzing"
    logger.info("Auto-analyze: starting security analysis on %d user doc(s)...", len(_user_doc_sources))
    try:
        user_sources = list(_user_doc_ingest_order) if _user_doc_ingest_order else sorted(_user_doc_sources)
        max_sources = max(1, int(app_config.AUTO_ANALYZE_MAX_SOURCES))
        selected_sources = user_sources[-max_sources:] if len(user_sources) > max_sources else user_sources
        if len(user_sources) > max_sources:
            logger.info(
                "Auto-analyze: limiting sources for startup pass (%d/%d): %s",
                len(selected_sources), len(user_sources), selected_sources,
            )
        # Do not use foreground analysis lock here: startup analysis should not block
        # interactive /api/chat and /analyze requests for minutes.
        result = analyze_for_bola(
            store,
            custom_query=_AUTO_ANALYZE_QUERY,
            n_context=app_config.AUTO_ANALYZE_N_CONTEXT,
            source_filter=selected_sources,
            timeout=app_config.AUTO_ANALYZE_TIMEOUT_SECONDS,
        )
        _auto_analysis_result = result
        _auto_analysis_status = "done"
        logger.info("Auto-analyze: done, report_len=%d", len(result or ""))
    except Exception as e:
        logger.exception("Auto-analyze: failed: %s", e)
        _auto_analysis_status = f"error: {e}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _auto_ingest_status
    _auto_ingest_status = "starting"
    t = threading.Thread(target=_auto_ingest_and_analyze, daemon=True)
    t.start()
    yield


def create_app() -> FastAPI:
    setup_logging(level=getattr(app_config, "LOG_LEVEL", "INFO"))
    log_memory(logger, "create_app start")
    app = FastAPI(
        title="BOLA AI",
        description="Local AI agent for security vulnerability analysis from documentation and traces",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.get("/health")
    def health():
        from bola_ai.agent.llm import is_available
        ollama_ok = is_available()
        ingesting = _auto_ingest_status not in ("idle", "done")
        try:
            store = get_store()
            chunks = store.count()
        except Exception:
            chunks = 0
        logger.info("Health check: ollama=%s chunks=%s user_docs=%s auto_ingest=%s",
                     ollama_ok, chunks, len(_user_doc_sources), _auto_ingest_status)
        return {
            "status": "ok",
            "ollama": ollama_ok,
            "documents_chunks": chunks,
            "user_documents": len(_user_doc_sources),
            "user_doc_sources": sorted(_user_doc_sources),
            "auto_ingest_status": _auto_ingest_status,
            "auto_analysis_status": _auto_analysis_status,
        }

    @app.get("/api/auto_analysis")
    def auto_analysis():
        """Return the auto-analysis result if available."""
        return {
            "status": _auto_analysis_status,
            "report": _auto_analysis_result,
            "user_doc_sources": sorted(_user_doc_sources),
            "auto_analyze_max_sources": app_config.AUTO_ANALYZE_MAX_SOURCES,
        }

    @app.post("/reset")
    def reset_store():
        """Clear the document store (for testing: ensures each test case runs with only the ingested doc)."""
        global _auto_analysis_result, _auto_analysis_status
        store = get_store()
        with _store_ops_lock:
            store.reset()
            _user_doc_sources.clear()
            _user_doc_ingest_order.clear()
        _auto_analysis_result = None
        _auto_analysis_status = "idle"
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
            _safe_add_document(store, content, source=source)
            _track_user_doc(source)
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
            src_name = file.filename or "upload"
            _safe_add_document(store, text, source=src_name)
            _track_user_doc(src_name)
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
        src_name = source or target.name
        _safe_add_document(store, text, source=src_name)
        _track_user_doc(src_name)
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
        """Run security analysis on ingested docs. Optional custom query."""
        store = get_store()
        query = body.query if body and body.query else None
        logger.info("Analyze: query=%s chunks_available=%s", query or "(default)", store.count())
        if _auto_analysis_status == "analyzing":
            raise HTTPException(
                429,
                "Startup auto-analysis is currently running. Wait for it to finish "
                "or check GET /api/auto_analysis, then retry your query.",
            )
        try:
            user_sources = sorted(_user_doc_sources) if _user_doc_sources else None
            if is_fast_path_query(query):
                result = analyze_for_bola(
                    store,
                    custom_query=query,
                    source_filter=user_sources,
                )
            else:
                result = _run_serialized_analysis(
                    store,
                    query=query,
                    source_filter=user_sources,
                    caller="api_analyze",
                )
            result = _finalize_analysis_output(result, query or "")
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

**I'm a local, offline security analysis tool (BOLA prioritized, broad taxonomy supported).** Here's how to talk to me:

### Getting Started
1. **Copy your API documentation** (markdown, text, HAR analysis) into the `shared_docs/` folder
2. **Tell me to ingest:** Type `ingest` to load all files, or `ingest <filename>` for a specific one
3. **Ask me questions:** "What security risks exist?" or "Generate curl commands to test authorization on GET /api/users/{id}"

### Commands I Understand
| What you say | What I do |
|---|---|
| `help` or `how do I use this?` | Show this guide |
| `ingest <filename>` | Ingest a specific file from `shared_docs/` |
| `ingest` or `documents are ready` | Ingest **all** files from `shared_docs/` at once |
| `list files` or `what files are available?` | List files in `shared_docs/` |
| `status` | Show system health and chunk count |
| `reset` | Clear all ingested documents |
| Any security analysis question | Run analysis on ingested docs |

### Example Conversation
```
You: documents are ready
Bot: ✓ Ingested 3 files (24 chunks total)

You: ingest my-api-spec.md
Bot: ✓ Ingested my-api-spec.md (12 chunks)

You: What security vulnerabilities exist in this API?
Bot: ## Potential findings ...

You: Generate curl commands to test authorization on GET /users/{id} with two tokens
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
            user_docs_info = f"**{len(_user_doc_sources)}** ({', '.join(sorted(_user_doc_sources))})" if _user_doc_sources else "None"
            return {
                "role": "assistant",
                "content": (
                    f"**System status:**\n"
                    f"- Ollama: {'online' if ollama_ok else 'offline'}\n"
                    f"- Total chunks in store: {store.count()}\n"
                    f"- User documents ingested: {user_docs_info}\n"
                    f"- Shared docs folder: `shared_docs/` (in your project directory)"
                ),
                "type": "info",
            }

        # Reset
        if msg_lower in ("reset", "clear", "start over"):
            store = get_store()
            with _store_ops_lock:
                store.reset()
                _user_doc_sources.clear()
                _user_doc_ingest_order.clear()
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

        _bulk_triggers = (
            "ingest", "ingest all", "load all", "import all",
            "documents are ready", "docs are ready", "files are ready",
            "ready to ingest", "ready to analyze", "i copied the documents",
            "i copied the files", "i put the files", "all files",
            "get the files", "get my files", "get files", "get the documents",
            "get my documents", "get documents", "get my docs", "get docs",
            "investigate", "investigate my files", "investigate my documents",
            "investigate the files", "investigate the documents",
            "take a look", "take a look at my files", "take a look at my documents",
            "scan", "scan the folder", "scan my files", "scan the files",
            "scan my documents", "scan the documents",
            "check my docs", "check my files", "check the files", "check the documents",
            "analyze my files", "analyze my documents", "analyze the files",
            "read the documents", "read my documents", "read the files", "read my files",
            "look at my files", "look at the files", "look at my documents",
            "process the docs", "process the files", "process my files",
            "process my documents", "process the documents",
            "load the files", "load my files", "load the documents", "load my documents",
            "read the folder", "read shared folder", "read the shared folder",
        )
        is_bulk = msg_lower.strip() in _bulk_triggers or _re.search(
            r"\b(?:ready|copied|put|placed|added|get|investigate|scan|check|look|take|process|analyze|read|load)\b"
            r".*\b(?:documents?|files?|docs?|folder)\b",
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
            _safe_add_document(store, text, source=filename)
            _track_user_doc(filename)
            n = store.count()
            return {
                "role": "assistant",
                "content": f"Ingested **{filename}** ({len(text):,} chars, {n} total chunks).\n\nYou can now ask me about security risks in this document.",
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
                    _safe_add_document(store, text, source=f.name)
                    _track_user_doc(f.name)
                    ingested.append(f"- **{f.name}** ({len(text):,} chars)")
                except UnicodeDecodeError:
                    errors.append(f"- `{f.name}` (skipped — not UTF-8)")
            n = store.count()
            parts = [f"Ingested **{len(ingested)} file(s)** from `shared_docs/` ({n} total chunks):\n"]
            parts.append("\n".join(ingested))
            if errors:
                parts.append("\n\n**Skipped:**\n" + "\n".join(errors))
            parts.append("\n\nYou can now ask me about security risks in these documents.")
            return {"role": "assistant", "content": "".join(parts), "type": "info"}

        # Default: security analysis — requires user documents
        store = get_store()
        if not has_user_docs():
            shared_root = app_config.SHARED_DOCS_DIR.resolve()
            available = []
            if shared_root.exists():
                available = [f.name for f in sorted(shared_root.iterdir()) if f.is_file() and not f.name.startswith(".")]
            if available:
                file_list = "\n".join(f"- `{f}`" for f in available[:15])
                return {
                    "role": "assistant",
                    "content": (
                        "**No documents have been ingested yet.** I can only analyze security risks in your documentation, not generic patterns.\n\n"
                        f"**Files available in `shared_docs/` ({len(available)}):**\n{file_list}\n\n"
                        "Say **ingest** to load all files, or **ingest <filename>** for a specific one.\n\n"
                        "Type **help** for full usage guide."
                    ),
                    "type": "info",
                }
            return {
                "role": "assistant",
                "content": (
                    "**No documents have been ingested yet.** I need your documentation to analyze security risks.\n\n"
                    "**How to get started:**\n"
                    "1. Copy your API documentation (markdown, text, HAR logs) into the `shared_docs/` folder\n"
                    "2. Say **ingest** to load all files, or **ingest <filename>** for a specific one\n"
                    "3. Then ask me about security risks\n\n"
                    "Type **help** for full usage guide."
                ),
                "type": "info",
            }
        try:
            if _auto_analysis_status == "analyzing":
                return {
                    "role": "assistant",
                    "content": (
                        "Startup auto-analysis is currently running on ingested files. "
                        "To avoid a long queue wait, please retry in a moment or check "
                        "`GET /api/auto_analysis` for readiness."
                    ),
                    "type": "info",
                }
            user_sources = sorted(_user_doc_sources) if _user_doc_sources else None
            if is_fast_path_query(msg):
                result = analyze_for_bola(
                    store,
                    custom_query=msg,
                    source_filter=user_sources,
                )
            else:
                result = _run_serialized_analysis(
                    store,
                    query=msg,
                    source_filter=user_sources,
                    caller="chat",
                )
            result = _finalize_analysis_output(result, msg)
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
    <p>Local security analysis. Use API: POST /ingest, POST /analyze.</p>
    </body>
    </html>
    """


def _chat_html() -> str:
    html = Path(__file__).parent / "chat.html"
    if html.exists():
        return html.read_text(encoding="utf-8")
    return "<html><body><h1>BOLA AI Chat</h1><p>chat.html not found</p></body></html>"
