#!/bin/sh
set -e

echo "=========================================="
echo "  BOLA AI — Starting (all-in-one)"
echo "  Model: ${OLLAMA_MODEL:-bola-analyzer}"
echo "  Knowledge: BOLA security examples (pre-loaded)"
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

# --- 2. Verify model is available (pre-baked at build time) ---
MODEL_NAME="${OLLAMA_MODEL:-bola-analyzer}"
ALLOW_MODEL_PULL="${BOLA_AI_ALLOW_MODEL_PULL:-1}"
MODEL_READY=0

if ollama list 2>/dev/null | grep -q "${MODEL_NAME}"; then
  echo "[bola-ai] Model ${MODEL_NAME} ready (pre-baked)."
  MODEL_READY=1
fi

# Fallback: pull base model from internet if pre-baked model is missing
# (should not normally happen; image is self-contained)
if [ "$MODEL_READY" = "0" ]; then
  if [ "$ALLOW_MODEL_PULL" = "1" ]; then
    echo "[bola-ai] Pre-baked model not found — pulling qwen2.5-coder:3b from internet..."
    ollama pull qwen2.5-coder:3b && \
      ollama create "${MODEL_NAME}" -f /app/Modelfile && \
      echo "[bola-ai] Base model ready." && \
      MODEL_READY=1
  fi
fi

if [ "$MODEL_READY" = "0" ]; then
  echo "[bola-ai] ERROR: No model available. Set BOLA_AI_ALLOW_MODEL_PULL=1 to allow internet fallback."
  exit 1
fi

# --- 3. Preload RAG knowledge (skip if already baked into image) ---
if [ "$BOLA_AI_PRELOAD" != "0" ] && { [ ! -d /data/chroma ] || [ -z "$(ls -A /data/chroma 2>/dev/null)" ]; }; then
  echo "[bola-ai] Preloading RAG knowledge base..."
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
