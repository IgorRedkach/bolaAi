#!/bin/sh
# Live API QA: run the stack (or use existing), then test health, ingest, and analyze via API.
# Usage: from repo root, run:
#   sh scripts/qa_api_live.sh [API_BASE_URL]
# If API_BASE_URL is not given, uses http://localhost:8000. Optionally starts Docker stack first if BOLA_AI_START_STACK=1.
# Exit 0 only if all steps PASS.

set -e
API="${1:-http://localhost:8000}"
START_STACK="${BOLA_AI_START_STACK:-0}"

cd "$(dirname "$0")/.."
FAIL=0

run_test() {
  name="$1"
  if [ "$2" = "PASS" ]; then
    echo "[PASS] $name"
  else
    echo "[FAIL] $name"
    FAIL=1
  fi
}

if [ "$START_STACK" = "1" ]; then
  echo "Starting Docker stack..."
  docker compose -f docker/docker-compose.yml up -d
  echo "Waiting for API..."
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -s -o /dev/null -w "%{http_code}" "$API/health" 2>/dev/null | grep -q 200; then break; fi
    sleep 2
  done
fi

echo "=== Live API QA: $API ==="

# 1. GET /health
echo ""
echo "1. GET /health"
code=$(curl -s -o /tmp/bola_health.json -w "%{http_code}" "$API/health" 2>/dev/null || echo "000")
if [ "$code" = "200" ]; then
  status=$(python3 -c "import json; print(json.load(open('/tmp/bola_health.json')).get('status',''))" 2>/dev/null || echo "")
  chunks=$(python3 -c "import json; print(json.load(open('/tmp/bola_health.json')).get('documents_chunks',-1))" 2>/dev/null || echo -1)
  if [ "$status" = "ok" ] && [ "$chunks" != "-1" ]; then
    run_test "GET /health -> 200, status=ok, documents_chunks=$chunks" PASS
  else
    run_test "GET /health -> 200 but invalid body (status=$status, chunks=$chunks)" FAIL
  fi
else
  run_test "GET /health -> $code (expected 200)" FAIL
fi

# 2. POST /ingest
echo ""
echo "2. POST /ingest (fake data)"
ingest_resp=$(curl -s -w "\n%{http_code}" -X POST "$API/ingest" \
  -F "content=GET /api/users/{id} returns user. No ownership check. GET /api/patients/{id} returns patient. No caller verification." \
  -F "source=qa_live" 2>/dev/null || echo '{"detail":"error"}\n000')
code=$(echo "$ingest_resp" | tail -1)
body=$(echo "$ingest_resp" | sed '$d')
if [ "$code" = "200" ]; then
  msg=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message','') or d.get('detail',''))" 2>/dev/null || echo "")
  chunks=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('chunks',-1))" 2>/dev/null || echo -1)
  if echo "$msg" | grep -qi "ingest\|ok" || [ "$chunks" != "-1" ]; then
    run_test "POST /ingest -> 200, chunks=$chunks" PASS
  else
    run_test "POST /ingest -> 200 but unexpected body" FAIL
  fi
else
  run_test "POST /ingest -> $code (expected 200)" FAIL
fi

# 3. GET /health again (chunks should be >= 1)
echo ""
echo "3. GET /health (chunk count after ingest)"
code=$(curl -s -o /tmp/bola_health2.json -w "%{http_code}" "$API/health" 2>/dev/null || echo "000")
chunks=$(python3 -c "import json; print(json.load(open('/tmp/bola_health2.json')).get('documents_chunks',0))" 2>/dev/null || echo 0)
if [ "$code" = "200" ] && [ "$chunks" -ge 1 ] 2>/dev/null; then
  run_test "GET /health after ingest -> chunks=$chunks" PASS
else
  run_test "GET /health after ingest -> code=$code chunks=$chunks" FAIL
fi

# 4. POST /analyze
echo ""
echo "4. POST /analyze"
analyze_resp=$(curl -s -w "\n%{http_code}" -X POST "$API/analyze" \
  -H "Content-Type: application/json" \
  -d '{"query": "Identify BOLA risks and suggest verification steps."}' \
  --max-time 120 2>/dev/null || echo '{"detail":"timeout"}\n000')
code=$(echo "$analyze_resp" | tail -1)
body=$(echo "$analyze_resp" | sed '$d')
if [ "$code" = "200" ]; then
  status=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status',''))" 2>/dev/null || echo "")
  report=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('report','')))" 2>/dev/null || echo 0)
  if [ "$status" = "ok" ] && [ "$report" -gt 50 ] 2>/dev/null; then
    run_test "POST /analyze -> 200, report length=$report" PASS
  else
    run_test "POST /analyze -> 200 but status=$status or short report (len=$report)" FAIL
  fi
else
  run_test "POST /analyze -> $code (expected 200; if 500, Ollama/model may be unavailable)" FAIL
fi

# 5. GET / (UI)
echo ""
echo "5. GET / (UI)"
code=$(curl -s -o /dev/null -w "%{http_code}" "$API/" 2>/dev/null || echo "000")
if [ "$code" = "200" ]; then
  run_test "GET / -> 200" PASS
else
  run_test "GET / -> $code" FAIL
fi

echo ""
if [ "$FAIL" -eq 0 ]; then
  echo "=== All live API checks PASSED ==="
  exit 0
else
  echo "=== Some checks FAILED ==="
  exit 1
fi
