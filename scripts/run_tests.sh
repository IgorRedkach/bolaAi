#!/bin/sh
# Full suite: live E2E is mandatory (test_e2e_llm, test_issues_resolved, test_api_live).
# Start stack first: cd docker && docker compose up -d && PYTHONPATH=src python -m bola_ai.cli health --wait
# CI without GPU: BOLA_AI_SKIP_LIVE_E2E=1 sh scripts/run_tests.sh
cd "$(dirname "$0")/.."
export PYTHONPATH=src
export BOLA_AI_FAKE_EMBEDDER=1
export BOLA_AI_LIVE_URL="${BOLA_AI_LIVE_URL:-http://localhost:8000}"
exec pytest tests/ -v "$@"
