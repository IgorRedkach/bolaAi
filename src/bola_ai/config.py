"""Configuration for BOLA AI (env and defaults)."""

import os
from pathlib import Path

# Paths
DATA_DIR = Path(os.environ.get("BOLA_AI_DATA", "data"))
CHROMA_PATH = DATA_DIR / "chroma"
COLLECTION_NAME = "bola_docs"
SHARED_DOCS_DIR = Path(os.environ.get("BOLA_AI_SHARED_DOCS_DIR", "/shared-docs"))

# Ollama
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL") or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
if OLLAMA_BASE_URL and not OLLAMA_BASE_URL.startswith("http"):
    OLLAMA_BASE_URL = f"http://{OLLAMA_BASE_URL}"
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:1.5b")

# Embeddings (local, small model for offline use)
EMBEDDING_MODEL = os.environ.get("BOLA_AI_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# API
API_HOST = os.environ.get("BOLA_AI_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("BOLA_AI_PORT", "8000"))

# --- Inference (LLM "ready to talk"): CPU inference with rich context can take 5-10 minutes.
# Ollama chat completion max wait (seconds). Default 600 for CPU; GPU users can lower.
LLM_CHAT_TIMEOUT_SECONDS = float(os.environ.get("BOLA_AI_LLM_CHAT_TIMEOUT", "600"))
# HTTP client timeout for POST /analyze only — must be >= LLM_CHAT_TIMEOUT_SECONDS so the client does not abort first.
ANALYZE_CLIENT_TIMEOUT = float(os.environ.get("BOLA_AI_ANALYZE_CLIENT_TIMEOUT", "660"))

# --- Learning from documents (ingest / embedding / chunking): can be slow on CPU; separate from inference.
# CLI and scripts use this for POST /ingest (not for /analyze).
INGEST_HTTP_TIMEOUT = float(os.environ.get("BOLA_AI_INGEST_TIMEOUT", "600"))

# --- Stack startup / training (Ollama up, model listed, first embed load): not LLM reply latency.
# Max seconds CLI `health --wait` polls until API reports ollama ready.
STACK_READY_WAIT_SECONDS = float(os.environ.get("BOLA_AI_STACK_WAIT_SECONDS", "900"))
# Ollama /api/tags probe (cold start); not chat inference.
OLLAMA_STARTUP_PROBE_TIMEOUT = float(os.environ.get("BOLA_AI_OLLAMA_STARTUP_PROBE_TIMEOUT", "60"))

# Test / low-memory: use fake embedder (no sentence-transformers load)
USE_FAKE_EMBEDDER = os.environ.get("BOLA_AI_FAKE_EMBEDDER", "").lower() in ("1", "true", "yes")

# RAG: max chunks sent to LLM (higher = richer context for complex docs like HAR files)
N_CONTEXT = int(os.environ.get("BOLA_AI_N_CONTEXT", "20"))
# Optional cap on total context string length (chars); 0 = no cap
MAX_CONTEXT_CHARS = int(os.environ.get("BOLA_AI_MAX_CONTEXT_CHARS", "0"))

# Logging
LOG_LEVEL = os.environ.get("BOLA_AI_LOG_LEVEL", "INFO")
