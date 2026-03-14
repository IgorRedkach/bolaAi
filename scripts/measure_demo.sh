#!/bin/sh
# Measure memory: agent (this script/shell) and tool (pytest, then API) at each step.
# Target: tool <= 10 GB, agent/IDE <= 6 GB; system has 32 GB.
# Usage: from repo root, sh scripts/measure_demo.sh

set -e
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

rss_self() {
    if [ -r /proc/self/status ]; then
        awk '/VmRSS:/ { print $2/1024 " MB" }' /proc/self/status
    else
        echo "N/A"
    fi
}

echo "=== Step 0: agent (measure script) RSS ==="
rss_self

echo ""
echo "=== Step 1: run tests (tool = pytest, fake embedder) ==="
export BOLA_AI_FAKE_EMBEDDER=1
export PYTHONPATH=src
python -m pytest tests/ -v --tb=short 2>&1 | tee /tmp/bola_pytest_out.txt || true
echo "[memory] agent after pytest:"; rss_self
echo "[memory] tool (pytest) see session start/end above in test output"

echo ""
echo "=== Step 2: run API demo (tool = uvicorn), log memory at each request ==="
export BOLA_AI_FAKE_EMBEDDER=1
export BOLA_AI_LOG_MEMORY=1
export PYTHONPATH=src
LOG=/tmp/bola_api_log.txt
python -m uvicorn bola_ai.api.app:create_app --host 127.0.0.1 --port 8000 --factory 2>"$LOG" &
API_PID=$!
echo "API PID $API_PID"
sleep 3
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -s -o /dev/null http://127.0.0.1:8000/health 2>/dev/null; then break; fi
    sleep 1
done
echo "[memory] agent before curl:"; rss_self
curl -s http://127.0.0.1:8000/health
echo ""
curl -s -X POST http://127.0.0.1:8000/ingest -F 'content=GET /api/users/{id} returns user. No ownership check documented.' -F 'source=demo'
echo ""
curl -s -X POST http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' -d '{"query": "BOLA risks and verification steps"}' | head -c 500
echo ""
echo "[memory] agent after curl:"; rss_self
kill $API_PID 2>/dev/null || true
wait $API_PID 2>/dev/null || true
echo ""
echo "=== Tool (API) memory from server log ==="
grep -E '\[memory\]' "$LOG" || true
echo ""
echo "=== Demo done. Tool should stay under 10 GB; agent under 6 GB on 32 GB system. ==="
