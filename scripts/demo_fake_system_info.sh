#!/bin/sh
# Demo: send fake/sample system info to the API and get BOLA suggestions.
# Requires the API to be running (e.g. docker compose up, or uvicorn).
# Usage: sh scripts/demo_fake_system_info.sh [API_BASE_URL]

set -e
API="${1:-http://localhost:8000}"

FAKE_SYSTEM_INFO="
# Sample API (fake system info for demo)

## Users API
- GET /api/users/{id} — returns user by ID. Auth: Bearer token.
- No documentation of ownership or tenant checks.

## Patients API (healthcare)
- GET /api/patients/{patientId} — returns patient record. Requires login.
- Request uses patientId in path; no mention of verifying caller is allowed to see this patient.

## Internal
- GET /api/internal/cases — list cases. Linked table: case_team_members (no access control documented).
"

echo "Ingesting fake system info..."
curl -s -X POST "$API/ingest" \
  -F "content=$FAKE_SYSTEM_INFO" \
  -F "source=demo_fake_system"

echo ""
echo "Requesting BOLA analysis..."
curl -s -X POST "$API/analyze" \
  -H "Content-Type: application/json" \
  -d '{"query": "Identify BOLA risks and suggest verification steps."}' | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('status') == 'ok':
    print(d.get('report', 'No report'))
else:
    print('Error:', d)
"
