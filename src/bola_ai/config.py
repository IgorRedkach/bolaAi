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
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "bola-analyzer")
OLLAMA_NUM_CTX = int(os.environ.get("BOLA_AI_OLLAMA_NUM_CTX", "8192"))
OLLAMA_NUM_PREDICT = int(os.environ.get("BOLA_AI_OLLAMA_NUM_PREDICT", "768"))

# Embeddings (local, small model for offline use)
EMBEDDING_MODEL = os.environ.get("BOLA_AI_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# API
API_HOST = os.environ.get("BOLA_AI_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("BOLA_AI_PORT", "8000"))

# --- Inference (LLM "ready to talk"): local-model baseline for broad hardware.
# Ollama chat completion max wait (seconds). Default 900 (15 min) for CPU-heavy cases.
LLM_CHAT_TIMEOUT_SECONDS = float(os.environ.get("BOLA_AI_LLM_CHAT_TIMEOUT", "900"))
# HTTP client timeout for POST /analyze only — must be >= LLM_CHAT_TIMEOUT_SECONDS so the client does not abort first.
ANALYZE_CLIENT_TIMEOUT = float(os.environ.get("BOLA_AI_ANALYZE_CLIENT_TIMEOUT", "960"))

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
N_CONTEXT = int(os.environ.get("BOLA_AI_N_CONTEXT", "12"))
# Optional cap on total context string length (chars); 0 = no cap
MAX_CONTEXT_CHARS = int(os.environ.get("BOLA_AI_MAX_CONTEXT_CHARS", "12000"))

# Logging
LOG_LEVEL = os.environ.get("BOLA_AI_LOG_LEVEL", "INFO")

# Startup automation
AUTO_ANALYZE_ON_STARTUP = os.environ.get("BOLA_AI_AUTO_ANALYZE_ON_STARTUP", "1").lower() in ("1", "true", "yes")
# Startup auto-analysis tuning.
# Timeout raised to 900 s (15 min) — CPU-only inference on a cold model can exceed 7 min
# for large HAR files; 420 s was too tight for first-run cold starts.
AUTO_ANALYZE_TIMEOUT_SECONDS = float(os.environ.get("BOLA_AI_AUTO_ANALYZE_TIMEOUT", "900"))
AUTO_ANALYZE_N_CONTEXT = int(os.environ.get("BOLA_AI_AUTO_ANALYZE_N_CONTEXT", "6"))
AUTO_ANALYZE_MAX_SOURCES = int(os.environ.get("BOLA_AI_AUTO_ANALYZE_MAX_SOURCES", "2"))
# Limit output tokens for startup auto-analysis to keep generation fast.
# Interactive /analyze calls use the full OLLAMA_NUM_PREDICT budget (768).
AUTO_ANALYZE_NUM_PREDICT = int(os.environ.get("BOLA_AI_AUTO_ANALYZE_NUM_PREDICT", "512"))
