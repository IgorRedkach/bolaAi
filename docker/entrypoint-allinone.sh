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

# --- 2. Set up model (from trained bundle or base pull) ---
MODEL_NAME="${OLLAMA_MODEL:-bola-analyzer}"
ALLOW_MODEL_PULL="${BOLA_AI_ALLOW_MODEL_PULL:-1}"
MODEL_READY=0

if ollama list 2>/dev/null | grep -q "${MODEL_NAME}"; then
  echo "[bola-ai] Model ${MODEL_NAME} already loaded."
  MODEL_READY=1
fi

# Try importing trained bundle (preferred — offline, deterministic)
if [ "$MODEL_READY" = "0" ] && [ -f /app/models/published/LATEST ]; then
  BUNDLE_NAME=$(cat /app/models/published/LATEST | tr -d '\n\r')
  BUNDLE_DIR="/app/models/published/${BUNDLE_NAME}"
  if ls "${BUNDLE_DIR}"/trained_model_bundle.part-* >/dev/null 2>&1; then
    echo "[bola-ai] Importing trained model bundle: ${BUNDLE_NAME}..."
    cat "${BUNDLE_DIR}"/trained_model_bundle.part-* > /tmp/trained_model_bundle.tar && \
    tar -xf /tmp/trained_model_bundle.tar -C /app/models/published && \
    rm -f /tmp/trained_model_bundle.tar
    # q4_K_M avoids F16 path; pair with Ollama v0.20.5 in the image (0.20.7+ can still hit llama_sampler on some bundles).
    if ollama create "${MODEL_NAME}" --quantize q4_K_M -f /app/models/published/active/Modelfile 2>&1; then
      echo "[bola-ai] Trained bundle imported successfully."
      MODEL_READY=1
    else
      echo "[bola-ai] Bundle import failed — falling back to base model pull."
    fi
  fi
fi

# Fallback: pull base model from internet (requires BOLA_AI_ALLOW_MODEL_PULL=1)
if [ "$MODEL_READY" = "0" ]; then
  if [ "$ALLOW_MODEL_PULL" = "1" ]; then
    echo "[bola-ai] Pulling qwen2.5-coder:3b base model (requires internet)..."
    # Base model is already quantized upstream; only add Modelfile/teaching — no re-quantize.
    ollama pull qwen2.5-coder:3b && ollama create "${MODEL_NAME}" -f /app/Modelfile
    echo "[bola-ai] Base model ready."
    MODEL_READY=1
  else
    echo "[bola-ai] ERROR: No model found and BOLA_AI_ALLOW_MODEL_PULL=0."
    echo "[bola-ai] Set BOLA_AI_ALLOW_MODEL_PULL=1 to allow internet fallback."
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
