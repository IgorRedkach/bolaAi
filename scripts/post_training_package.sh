#!/usr/bin/env bash
# Run after training completes: merge adapter → package → rebuild Docker → push.
# Usage:
#   bash scripts/post_training_package.sh [--run-dir models/adapters/qlora_<ts>]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[$(date -u +%H:%M:%S)] POST-TRAINING PACKAGING STARTED"
echo "[$(date -u +%H:%M:%S)] RAM at start:"
free -h | grep Mem

# Resolve adapter run dir — use explicit arg or auto-detect latest
if [[ "${1:-}" == "--run-dir" && -n "${2:-}" ]]; then
    RUN_DIR="$2"
else
    # Latest adapter dir by mtime
    RUN_DIR=$(find models/adapters -maxdepth 1 -name "qlora_*" -type d \
        | xargs ls -dt 2>/dev/null | head -1)
    if [[ -z "$RUN_DIR" ]]; then
        echo "ERROR: No adapter directory found under models/adapters/. Run training first."
        exit 1
    fi
fi
echo "[$(date -u +%H:%M:%S)] Using adapter: $RUN_DIR"

# 1. Merge adapter into base model + package for Ollama
echo ""
echo "=== STEP 1: Merge adapter + create Ollama model bundle ==="
PYTHONPATH=scripts python scripts/package_trained_model_for_ollama.py \
    --run-dir "$RUN_DIR" \
    --model-name bola-analyzer \
    --modelfile-template docker/Modelfile \
    --skip-ollama-create \
    2>&1 | tee logs/package_model.log

echo ""
echo "[$(date -u +%H:%M:%S)] RAM after merge:"
free -h | grep Mem

# 2. Commit all changes (config, logs, model files)
echo ""
echo "=== STEP 2: Commit changes ==="
git add -A
git commit -m "$(cat <<'EOF'
feat: CPU LoRA fine-tune (3B, r=8) on 14 quality improvement examples

- Train Qwen2.5-Coder-3B-Instruct with LoRA r=8 (CPU float32, AVX2)
- 14 examples: 7 field injection + 7 write escalation across diverse domains
- 5 epochs, 128-token chunks, ~160 steps, memory guard throughout
- Adapter merged and packaged as bola-analyzer Ollama model
- New configs: qlora_quality_cpu.yaml, start_cpu_training.sh, mem_guard.py
EOF
)" || echo "[WARN] Nothing new to commit"

# 3. Push to trigger CI/CD
echo ""
echo "=== STEP 3: Push to main ==="
git push origin main

echo ""
echo "[$(date -u +%H:%M:%S)] DONE. CI/CD will rebuild and publish the Docker image."
echo "Wait ~10-15 min, then run: bash scripts/post_training_e2e_test.sh"
