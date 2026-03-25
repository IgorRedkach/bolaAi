#!/bin/sh
# Manual communication test: ingest sample doc, call analyze, print report and run checks.
# Use after each iteration to verify the app by talking to it. Requires API at API_BASE_URL.
# Usage: from repo root, BOLA_AI_ANALYZE_TIMEOUT=240 sh scripts/manual_communication_test.sh [API_BASE_URL]

set -e
API="${1:-http://localhost:8000}"
API="${API%/}"
TIMEOUT="${BOLA_AI_ANALYZE_TIMEOUT:-300}"
cd "$(dirname "$0")/.."

echo "=== Manual communication test: $API (timeout ${TIMEOUT}s) ==="
echo "1. Health..."
curl -s -o /dev/null -w "%{http_code}" "$API/health" | grep -q 200 || { echo "API not ready."; exit 1; }
echo " OK"

echo "2. Ingest sample doc..."
DOC="$(cat tests/fixtures/sample_project_documentation.md)"
curl -s -X POST "$API/ingest" -F "content=$DOC" -F "source=manual_test" | grep -q '"status":"ok"' || { echo "Ingest failed."; exit 1; }
echo " OK"

echo "3. Analyze (may take 1–3 min)..."
RESP="$(curl -s -X POST "$API/analyze" -H "Content-Type: application/json" -d '{"query": "Identify BOLA risks and give verification steps for each."}' --max-time "$TIMEOUT" -w "\n%{http_code}" -o /tmp/bola_manual_resp.json)"
HTTP_CODE="$(echo "$RESP" | tail -n1)"
if [ "$HTTP_CODE" != "200" ]; then
  echo " Analyze returned HTTP $HTTP_CODE. Response:"
  head -c 500 /tmp/bola_manual_resp.json
  exit 1
fi
echo " OK"

echo "4. Report checks..."
python3 -c "
import json, re
with open('/tmp/bola_manual_resp.json') as f:
    d = json.load(f)
r = d.get('report', '')
print('  Length:', len(r))
issues = []
if '### ###' in r or '#### ###' in r:
    issues.append('Duplicate heading (### ###)')
if re.search(r'/api/[^\s\[\]]*(?:users|tenants)[^\s\[\]]*', r):
    issues.append('Unredacted users/tenants path')
if len(r) > 200 and 'verification' not in r.lower() and 'Verification reminder' not in r:
    issues.append('No verification section or reminder')
if issues:
    print('  ISSUES:', issues)
else:
    print('  No issues detected.')
print()
print('--- Report (last 1200 chars) ---')
print(r[-1200:] if len(r) > 1200 else r)
print('--- End ---')
"
echo "Done. Review the report above; if issues appear, fix and re-run tests then restart app and this script."
