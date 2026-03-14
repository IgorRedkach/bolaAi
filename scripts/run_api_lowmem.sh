#!/bin/sh
# Run API in low-memory mode (fake embedder; no torch). Ingest + UI work; /analyze needs Ollama.
cd "$(dirname "$0")/.."
export BOLA_AI_FAKE_EMBEDDER=1
export PYTHONPATH=src
exec python run_api.py
