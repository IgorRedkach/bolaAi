#!/bin/sh
set -e
echo "[bola-ai] Entrypoint: BOLA_AI_DATA=$BOLA_AI_DATA OLLAMA_HOST=$OLLAMA_HOST OLLAMA_MODEL=$OLLAMA_MODEL"
if [ "$BOLA_AI_PRELOAD" != "0" ] && { [ ! -d /data/chroma ] || [ -z "$(ls -A /data/chroma 2>/dev/null)" ]; }; then
  echo "[bola-ai] Preloading RAG store with BOLA knowledge (one-time)..."
  if PYTHONPATH=/app/src python /app/src/training/load_knowledge.py; then
    echo "[bola-ai] RAG preload completed successfully."
  else
    echo "[bola-ai] Preload failed (e.g. OOM); set BOLA_AI_PRELOAD=0 to skip. Continuing."
  fi
else
  echo "[bola-ai] Skipping RAG preload (BOLA_AI_PRELOAD=$BOLA_AI_PRELOAD or /data/chroma already exists)."
fi
echo "[bola-ai] Starting uvicorn on 0.0.0.0:8000 ..."
exec uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory
