#!/usr/bin/env python3
"""Agent E2E: new doc → ingest → person Q&A including mandatory follow-ups (AGENT_PROMPT §5).

Minimum **6** separate POST /analyze calls:
  - q1–q3: initial risks / endpoints / GraphQL
  - q4–q6: more detail + 200 vs 403, fake-token curls from doc only, self-validation of paths

  BOLA_AI_E2E_FIXTURE=tests/fixtures/doc_onetime_energy_billing_api_20250318.md \\
    PYTHONPATH=src python scripts/run_agent_e2e_loop_once.py http://localhost:8000
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from bola_ai import config  # noqa: E402

SHARED_DOCS = ROOT / "shared_docs"
FIXTURE_ENV = os.environ.get("BOLA_AI_E2E_FIXTURE", "").strip()
FIXTURE_STATE_FILE = ROOT / "docs/e2e_fixture_rotation_state.json"
OUT = ROOT / "docs/e2e_loop_last_run.json"
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
BASE = BASE.rstrip("/")
TIMEOUT_INGEST = httpx.Timeout(config.INGEST_HTTP_TIMEOUT, connect=60.0)
TIMEOUT_ANALYZE = httpx.Timeout(config.ANALYZE_CLIENT_TIMEOUT, connect=60.0)
TIMEOUT_QUICK = httpx.Timeout(60.0, connect=30.0)

# Mandatory wider communication (person follow-up) — same for every loop
FOLLOWUPS: list[tuple[str, str]] = [
    (
        "q4_detail_runbook",
        "**STRICT:** Use ONLY endpoints and operations that appear in the ingested documentation excerpt. "
        "Do NOT mention GraphQL, SOQL, Salesforce, Lightning, or nested resolvers unless that exact technology "
        "appears in the excerpt. Do NOT write 'Assume the API has…' for features not in the doc. "
        "For the **single highest-risk** finding among **documented** endpoints only, produce a **numbered runbook** "
        "(at least 8 steps) for our SOC. Explain: if the second user's same request returns **200** vs **403**, "
        "what each means for BOLA.",
    ),
    (
        "q5_fake_curls",
        "I have **Bearer token_A** (user Alice, org Alpha) and **Bearer token_B** (user Bob, org Beta). "
        "Choose **one** object-by-ID endpoint that appears **verbatim** in the ingested documentation. "
        "Use fake id **obj-demo-9911**. Give **only** two curl commands—Alice then Bob—same URL path and **same HTTP method as in the doc** "
        "(if the doc says POST, use -X POST; if GET, use GET). Different Authorization headers only. "
        "Paths must match the documentation character-for-character; "
        "do not invent base URL hosts—use placeholder https://api.example.com if needed.",
    ),
    (
        "q6_validate_paths",
        "Review your **immediately previous** answer: list every HTTP path (e.g. /energy/v2/...) you cited. "
        "For each path, state YES if it appears in the ingested documentation text or NO if hallucinated.",
    ),
]


def _fixture_system_tag(path: Path) -> str:
    name = path.name.lower()
    for token in (
        "salesforce",
        "energy",
        "fleet",
        "banking",
        "healthcare",
        "claims",
        "permits",
        "hr",
        "wms",
        "procurement",
        "insurance",
        "edu",
        "gov",
        "retail",
        "iot",
    ):
        if token in name:
            return token
    return "general"


def _fixture_doc_type(path: Path, text: str) -> str:
    name = path.name.lower()
    low = text.lower()
    if "har" in name or '"log"' in low[:2000]:
        return "har_like"
    if "graphql" in low:
        return "graphql"
    if any(x in low for x in ("salesforce", "soql", "aura", "lightning")):
        return "salesforce_soql"
    return "rest_doc"


def _load_fixture_state() -> dict:
    if not FIXTURE_STATE_FILE.exists():
        return {"history": []}
    try:
        data = json.loads(FIXTURE_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"history": []}
    if not isinstance(data, dict):
        return {"history": []}
    history = data.get("history")
    if not isinstance(history, list):
        data["history"] = []
    return data


def _save_fixture_state(state: dict) -> None:
    FIXTURE_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _pick_diverse_fixture() -> tuple[Path, dict]:
    if FIXTURE_ENV:
        fixture = Path(FIXTURE_ENV)
        if not fixture.is_absolute():
            fixture = ROOT / fixture
        text = fixture.read_text(encoding="utf-8")
        return fixture, {
            "selection_mode": "explicit_env",
            "doc_type": _fixture_doc_type(fixture, text),
            "system": _fixture_system_tag(fixture),
        }

    fixtures = sorted((ROOT / "tests/fixtures").glob("*.md"))
    fixtures = [p for p in fixtures if p.name != "expected_outcomes.md"]
    if not fixtures:
        raise FileNotFoundError("No fixtures found under tests/fixtures")

    state = _load_fixture_state()
    history: list[dict] = [h for h in state.get("history", []) if isinstance(h, dict)]
    recent = history[-6:]
    last = history[-1] if history else {}
    last_type = str(last.get("doc_type", ""))
    last_system = str(last.get("system", ""))
    recent_types = {str(h.get("doc_type", "")) for h in recent}
    expected_types = {"rest_doc", "graphql", "salesforce_soql", "har_like"}
    missing_types = expected_types - recent_types

    best: tuple[int, Path, dict] | None = None
    for fixture in fixtures:
        text = fixture.read_text(encoding="utf-8")
        doc_type = _fixture_doc_type(fixture, text)
        system = _fixture_system_tag(fixture)
        score = 0
        if doc_type != last_type:
            score += 4
        if system != last_system:
            score += 3
        if doc_type in missing_types:
            score += 5
        if "salesforce" not in system and doc_type != "har_like":
            score += 1  # bias away from Salesforce/HAR dominance
        meta = {"doc_type": doc_type, "system": system}
        if best is None or score > best[0]:
            best = (score, fixture, meta)

    assert best is not None
    selected = best[1]
    selected_meta = best[2]
    history.append(
        {
            "fixture": str(selected.relative_to(ROOT)),
            "doc_type": selected_meta["doc_type"],
            "system": selected_meta["system"],
        }
    )
    state["history"] = history[-30:]
    _save_fixture_state(state)
    selected_meta["selection_mode"] = "auto_diverse_rotation"
    selected_meta["missing_types_before_pick"] = sorted(missing_types)
    return selected, selected_meta


def _initial_queries(name: str) -> list[tuple[str, str]]:
    n = name.lower()
    if "wms" in n:
        return [
            (
                "q1",
                "I'm auditing this WMS API — could a picker at one warehouse complete another site's "
                "pick tasks or read another bin by changing binId or taskId?",
            ),
            (
                "q2",
                "Only for POST /wms/v1/batch/picks: what BOLA risk and how do I prove it with two different API keys/users?",
            ),
            (
                "q3",
                "This documentation is REST-only (no GraphQL). List BOLA tests using only the three paths shown in the doc.",
            ),
        ]
    if "energy" in n:
        return [
            (
                "q1",
                "I'm reviewing this energy billing API for a utility — could one billing analyst pull "
                "another territory's meter or account data by changing IDs? What BOLA should we test first?",
            ),
            (
                "q2",
                "Focus on POST /energy/v2/accounts/bulk-usage: what goes wrong if IDs are not scoped per caller, "
                "and how do I prove it with two real user sessions?",
            ),
            (
                "q3",
                "For the GraphQL usagePoint(id) field — how would I verify object-level auth with two tokens on the same id?",
            ),
        ]
    if "fleet" in n:
        return [
            (
                "q1",
                "I'm auditing this fleet API — could one fleet manager read another company's telemetry by swapping vehicle IDs? "
                "What BOLA angles and two-session proof?",
            ),
            (
                "q2",
                "For POST /fleet/v1/bulk/location-history specifically: curl-style steps with two Bearer tokens and mixed fleet vehicle IDs.",
            ),
            (
                "q3",
                "GraphQL trip(id): two-token verification on the same trip id—spell it out.",
            ),
        ]
    return [
        (
            "q1",
            "As a security reviewer reading this API doc only: what are the top BOLA risks and how to test with two user sessions?",
        ),
        (
            "q2",
            "Pick the batch or bulk endpoint in the doc and describe two-token verification.",
        ),
        (
            "q3",
            "If the doc has GraphQL, how to verify BOLA with two tokens on the same object id?",
        ),
    ]


def _paths_in_doc(doc: str) -> set[str]:
    out: set[str] = set()
    for m in re.finditer(r"`(?:GET|POST|PATCH)\s+(/[^\s`]+)`", doc, re.I):
        out.add(m.group(1))
    for m in re.finditer(r"((?:GET|POST|PATCH)\s+/[a-z0-9./_{}-]+)", doc, re.I):
        out.add(m.group(1).split()[-1])
    for m in re.finditer(r"(\/(?:energy|fleet|permits|api)[/a-z0-9._{}-]+)", doc, re.I):
        out.add(m.group(1))
    return {p for p in out if len(p) > 6}


def _validate_q5_against_doc(doc: str, q5_report: str) -> dict:
    doc_paths = _paths_in_doc(doc)
    hits = [p for p in doc_paths if isinstance(p, str) and p in q5_report and len(p) > 5]
    return {
        "doc_path_count_estimate": len(doc_paths),
        "q5_contains_doc_subpath": len(hits) > 0,
        "matched_snippets": hits[:8],
    }


def main() -> int:
    fixture, fixture_meta = _pick_diverse_fixture()
    if not fixture.is_file():
        print(f"Fixture not found: {fixture}", file=sys.stderr)
        return 1
    doc = fixture.read_text(encoding="utf-8")
    er = os.environ.get("BOLA_AI_E2E_EXPECTED_JSON")
    log: dict = {
        "fixture": str(fixture),
        "fixture_selection": fixture_meta,
        "person_e2e_minimum": {
            "initial_person_questions": 3,
            "followup_detail_200_403": True,
            "followup_fake_token_curls": True,
            "followup_self_path_validation": True,
            "separate_post_analyze_each": True,
        },
        "steps": [],
    }
    if er:
        log["expected_risks"] = json.loads(er)

    with httpx.Client(timeout=TIMEOUT_QUICK) as c:
        r = c.post(f"{BASE}/reset")
        log["steps"].append({"name": "reset", "status": r.status_code})
        r.raise_for_status()

    with httpx.Client(timeout=TIMEOUT_INGEST) as c:
        use_shared = os.environ.get("BOLA_AI_E2E_USE_SHARED_VOLUME", "1").lower() in ("1", "true", "yes")
        if use_shared:
            SHARED_DOCS.mkdir(parents=True, exist_ok=True)
            shared_name = os.environ.get("BOLA_AI_E2E_SHARED_FILENAME", fixture.name)
            shared_path = SHARED_DOCS / shared_name
            shared_path.write_text(doc, encoding="utf-8")
            r = c.post(
                f"{BASE}/ingest_shared",
                data={"relative_path": shared_name, "source": fixture.stem},
            )
            log["steps"].append(
                {
                    "name": "ingest_shared",
                    "status": r.status_code,
                    "chunks": (r.json() or {}).get("chunks"),
                    "shared_relative_path": shared_name,
                }
            )
        else:
            r = c.post(f"{BASE}/ingest", data={"content": doc, "source": fixture.stem})
            log["steps"].append({"name": "ingest", "status": r.status_code, "chunks": (r.json() or {}).get("chunks")})
        r.raise_for_status()

    queries = _initial_queries(fixture.name) + FOLLOWUPS
    with httpx.Client(timeout=TIMEOUT_ANALYZE) as c:
        for key, q in queries:
            r = c.post(f"{BASE}/analyze", json={"query": q})
            rep = (r.json() or {}).get("report") or "" if r.status_code == 200 else ""
            log["steps"].append(
                {
                    "name": key,
                    "status": r.status_code,
                    "query_preview": q[:180],
                    "report_len": len(rep),
                }
            )
            log[f"report_{key}_full"] = rep

    q5 = log.get("report_q5_fake_curls_full", "")
    log["automated_checks"] = {
        "q5_grounding": _validate_q5_against_doc(doc, q5),
        "q6_expected_path_audit": "manual_read_report_q6",
    }

    OUT.write_text(json.dumps(log, indent=2)[:800000], encoding="utf-8")
    print("Wrote", OUT)
    print("Person E2E: 3 initial + 3 follow-up (detail, fake curls, path validation) = 6 analyze calls.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
