#!/usr/bin/env bash
# Pull new image and run E2E tests after CI/CD push.
# Usage: bash scripts/post_training_e2e_test.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "[$(date -u +%H:%M:%S)] Pulling latest image..."
docker compose pull

echo "[$(date -u +%H:%M:%S)] Starting container..."
docker compose up -d
sleep 10

echo "[$(date -u +%H:%M:%S)] Waiting for health..."
for i in $(seq 1 30); do
    STATUS=$(curl -sf http://localhost:8000/health 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "down")
    echo "  [$i/30] status=$STATUS"
    [[ "$STATUS" == "ok" ]] && break
    sleep 10
done

echo ""
echo "=== GATE 1 TEST: Field Injection ==="
curl -s -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Analyze this API: GET /v1/reports?fields=id,title,cost — the server returns all requested fields for authenticated users without checking if cost is restricted. One session, authenticated as employee. Does this have a BOLA vulnerability?"}' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('response','ERROR')[:1500])"

echo ""
echo "=== GATE 2 TEST: Write Escalation ==="
curl -s -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Analyze: POST /api/users/me/update with body {\"role\":\"admin\",\"name\":\"test\"} — the API accepts and persists the role field without validating it against the caller permission level. Single authenticated user session. Is this a BOLA/authorization vulnerability?"}' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('response','ERROR')[:1500])"

echo ""
echo "=== CURL EXAMPLE TEST ==="
curl -s -X POST http://localhost:8000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Give me a curl command to test for field injection on GET /api/v1/users/me?fields=id,email,salary — inject the salary field as an unauthorized user"}' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('response','ERROR')[:1500])"

echo ""
echo "[$(date -u +%H:%M:%S)] E2E test complete."
