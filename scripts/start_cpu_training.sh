#!/usr/bin/env bash
# Start 3B CPU training with memory guard.
# Usage: bash scripts/start_cpu_training.sh [--resume]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p logs

EXTRA_ARGS=""
if [[ "${1:-}" == "--resume" ]]; then
  EXTRA_ARGS="--resume latest"
fi

echo "[$(date -u +%H:%M:%S)] Starting 3B CPU training..."
echo "[$(date -u +%H:%M:%S)] Current RAM:"
free -h | grep Mem

PYTHONPATH=scripts python scripts/train_qlora_unsloth.py \
  --config configs/training/qlora_quality_cpu.yaml \
  --chunk-size-tokens 128 \
  --chunk-overlap-tokens 32 \
  $EXTRA_ARGS \
  > logs/training_quality_cpu.log 2>&1 &
TRAIN_PID=$!
echo "[$(date -u +%H:%M:%S)] Training PID: $TRAIN_PID"

# Start memory guard — kill training if available RAM < 1.5 GB
python scripts/mem_guard.py \
  --pid "$TRAIN_PID" \
  --min-avail-gb 1.5 \
  --interval 10 \
  --log logs/mem_guard.log \
  > logs/mem_guard.log 2>&1 &
GUARD_PID=$!
echo "[$(date -u +%H:%M:%S)] Memory guard PID: $GUARD_PID"

echo ""
echo "Monitor with:"
echo "  tail -f logs/training_quality_cpu.log | grep -v 'Loading weights'"
echo "  tail -f logs/mem_guard.log"
echo "  cat docs/retrain_live_heartbeat.json"
echo ""
echo "Resume after interrupt:"
echo "  bash scripts/start_cpu_training.sh --resume"
