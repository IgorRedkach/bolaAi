#!/bin/sh
# Run tests with fake embedder (no sentence-transformers/torch load)
cd "$(dirname "$0")/.."
export BOLA_AI_FAKE_EMBEDDER=1
export PYTHONPATH=src
exec pytest tests/ -v "$@"
