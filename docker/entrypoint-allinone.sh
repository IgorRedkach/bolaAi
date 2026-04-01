#!/bin/sh
set -e

echo "=========================================="
echo "  BOLA AI — Starting (all-in-one)"
echo "  Model: ${OLLAMA_MODEL:-bola-analyzer} (pre-baked)"
echo "  Knowledge: 215 BOLA examples (pre-loaded)"
echo "=========================================="

# --- 1. Start Ollama in the background ---
echo "[bola-ai] Starting Ollama server..."
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
echo "[bola-ai] Waiting for Ollama to be ready..."
for i in $(seq 1 60); do
  if ollama list >/dev/null 2>&1; then
    echo "[bola-ai] Ollama is ready."
    break
  fi
  if [ "$i" = "60" ]; then
    echo "[bola-ai] ERROR: Ollama did not start in 60 seconds."
    exit 1
  fi
  sleep 1
done

# --- 2. Verify model is present (baked into image during build) ---
MODEL_NAME="${OLLAMA_MODEL:-bola-analyzer}"
ALLOW_MODEL_PULL="${BOLA_AI_ALLOW_MODEL_PULL:-0}"
if ollama list 2>/dev/null | grep -q "${MODEL_NAME}"; then
  echo "[bola-ai] Model ${MODEL_NAME} found (pre-baked)."
else
  if [ "$ALLOW_MODEL_PULL" = "1" ]; then
    echo "[bola-ai] WARNING: ${MODEL_NAME} not found — creating from Modelfile..."
    echo "[bola-ai] Pulling qwen2.5-coder:7b (~4.7 GB, this requires internet)..."
    ollama pull qwen2.5-coder:7b
    ollama create "${MODEL_NAME}" -f /app/Modelfile
    echo "[bola-ai] Model ready."
  else
    echo "[bola-ai] ERROR: required model '${MODEL_NAME}' is missing in the image."
    echo "[bola-ai] Refusing runtime model pull to preserve offline/quality guarantees."
    echo "[bola-ai] Rebuild image or run with BOLA_AI_ALLOW_MODEL_PULL=1 to allow fallback."
    exit 1
  fi
fi

# --- 3. Preload RAG knowledge (skip if already baked into image) ---
if [ "$BOLA_AI_PRELOAD" != "0" ] && { [ ! -d /data/chroma ] || [ -z "$(ls -A /data/chroma 2>/dev/null)" ]; }; then
  echo "[bola-ai] Preloading RAG knowledge base (215 BOLA examples)..."
  if PYTHONPATH=/app/src python /app/src/training/load_knowledge.py; then
    echo "[bola-ai] RAG preload done."
  else
    echo "[bola-ai] RAG preload failed (continuing anyway)."
  fi
else
  echo "[bola-ai] RAG knowledge already loaded (pre-baked)."
fi

# --- 4. Start the web app ---
echo "=========================================="
echo "  Ready! Open http://localhost:8000/chat"
echo "=========================================="
exec uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory
