#!/bin/sh
set -e

echo "=========================================="
echo "  BOLA AI — Starting (all-in-one)"
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

# --- 2. Create model if not present ---
if ! ollama list 2>/dev/null | grep -q bola-analyzer; then
  echo "[bola-ai] Creating bola-analyzer model (first run — downloading ~1 GB)..."
  ollama pull qwen2.5-coder:1.5b
  ollama create bola-analyzer -f /app/Modelfile
  echo "[bola-ai] Model ready."
else
  echo "[bola-ai] Model bola-analyzer already exists."
fi

# --- 3. Preload RAG knowledge (first run only) ---
if [ "$BOLA_AI_PRELOAD" != "0" ] && { [ ! -d /data/chroma ] || [ -z "$(ls -A /data/chroma 2>/dev/null)" ]; }; then
  echo "[bola-ai] Preloading RAG knowledge base..."
  if PYTHONPATH=/app/src python /app/src/training/load_knowledge.py; then
    echo "[bola-ai] RAG preload done."
  else
    echo "[bola-ai] RAG preload failed (continuing anyway)."
  fi
else
  echo "[bola-ai] RAG already loaded."
fi

# --- 4. Start the web app ---
echo "=========================================="
echo "  Ready! Open http://localhost:8000/chat"
echo "=========================================="
exec uvicorn bola_ai.api.app:create_app --host 0.0.0.0 --port 8000 --factory
