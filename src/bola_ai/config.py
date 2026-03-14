"""Configuration for BOLA AI (env and defaults)."""

import os
from pathlib import Path

# Paths
DATA_DIR = Path(os.environ.get("BOLA_AI_DATA", "data"))
CHROMA_PATH = DATA_DIR / "chroma"
COLLECTION_NAME = "bola_docs"

# Ollama
OLLAMA_BASE_URL = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5-coder:1.5b")

# Embeddings (local, small model for offline use)
EMBEDDING_MODEL = os.environ.get("BOLA_AI_EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# API
API_HOST = os.environ.get("BOLA_AI_HOST", "0.0.0.0")
API_PORT = int(os.environ.get("BOLA_AI_PORT", "8000"))

# Test / low-memory: use fake embedder (no sentence-transformers load)
USE_FAKE_EMBEDDER = os.environ.get("BOLA_AI_FAKE_EMBEDDER", "").lower() in ("1", "true", "yes")

# RAG: max chunks sent to LLM (lower = less memory)
N_CONTEXT = int(os.environ.get("BOLA_AI_N_CONTEXT", "10"))
# Optional cap on total context string length (chars); 0 = no cap
MAX_CONTEXT_CHARS = int(os.environ.get("BOLA_AI_MAX_CONTEXT_CHARS", "0"))

# Logging
LOG_LEVEL = os.environ.get("BOLA_AI_LOG_LEVEL", "INFO")
