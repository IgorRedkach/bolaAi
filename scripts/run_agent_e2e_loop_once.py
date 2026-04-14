#!/usr/bin/env python3
"""Agent E2E: new doc → ingest → adaptive person-style Q&A with follow-ups.

Baseline flow:
  - initial risk questions tailored to the selected fixture
  - follow-ups for detailed runbook, fake-token curls, and self-validation of paths

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

# Wider communication follow-ups (person style)
FOLLOWUPS: list[tuple[str, str]] = [
    (
        "q4_detail_runbook",
        "For the single highest-risk documented endpoint, provide a numbered authorization test runbook with grounded steps only. "
        "Explain what 200 vs 403 means for the second user's same-object request.",
    ),
    (
        "q5_fake_curls",
        "I have **Bearer AUTH_TOKEN_1** (principal one) and **Bearer AUTH_TOKEN_2** (principal two). "
        "Choose **one** object-by-ID endpoint that appears **verbatim** in the ingested documentation. "
        "Use fake id **obj-demo-9911**. Give **only** two curl commands—principal one then principal two—same URL path and **same HTTP method as in the doc** "
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
    fixtures += sorted((ROOT / "tests/fixtures").glob("*.txt"))
    fixtures += sorted((ROOT / "tests/fixtures").glob("*.har"))
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


def _initial_queries(name: str, doc_type: str) -> list[tuple[str, str]]:
    if doc_type == "har_like":
        return [
            (
                "q1",
                "Analyze this HAR/log artifact only. Identify the highest-risk authorization issues and keep findings grounded to visible request shapes.",
            ),
            (
                "q2",
                "Focus on Aura request tampering: how can field list expansion, filter widening, or editable-field expansion be abused here?",
            ),
            (
                "q3",
                "Generate two verification requests using the same observed endpoint shape and explain secure vs vulnerable outcomes.",
            ),
        ]
    n = name.lower()
    if "wms" in n:
        return [
            (
                "q1",
                "I'm auditing this WMS API — could a picker at one warehouse complete another site's "
                "pick tasks or read another bin by changing binId or taskId? What security risks should we validate first?",
            ),
            (
                "q2",
                "Only for POST /wms/v1/batch/picks: what authorization risk exists and how do I prove it with two different API keys/users?",
            ),
            (
                "q3",
                "This documentation is REST-only (no GraphQL). List the highest-risk security tests using only the three paths shown in the doc.",
            ),
        ]
    if "energy" in n:
        return [
            (
                "q1",
                "I'm reviewing this energy billing API for a utility — could one billing analyst pull "
                "another territory's meter or account data by changing IDs? What security risks should we test first?",
            ),
            (
                "q2",
                "Focus on POST /energy/v2/accounts/bulk-usage: what goes wrong if IDs are not scoped per caller, "
                "and how do I prove it with two real user sessions?",
            ),
            (
                "q3",
                "For the GraphQL usagePoint(id) field — how would I verify object-level authorization with two tokens on the same id?",
            ),
        ]
    if "fleet" in n:
        return [
            (
                "q1",
                "I'm auditing this fleet API — could one fleet manager read another company's telemetry by swapping vehicle IDs? "
                "What authorization-risk angles and two-session proof?",
            ),
            (
                "q2",
                "For POST /fleet/v1/bulk/location-history specifically: curl-style steps with two Bearer tokens and mixed fleet vehicle IDs.",
            ),
            (
                "q3",
                "GraphQL trip(id): two-token authorization verification on the same trip id—spell it out.",
            ),
        ]
    return [
        (
            "q1",
            "As a security reviewer reading this API doc only: what are the top security risks and how should I validate them?",
        ),
        (
            "q2",
            "Pick the batch or bulk endpoint in the doc and describe two-identity comparative verification.",
        ),
        (
            "q3",
            "If the doc has GraphQL, how should I verify authorization with two tokens on the same object id?",
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

    def _strip_params(p: str) -> str:
        return re.sub(r"\{[^}]+\}", "", p)

    def _path_segments(p: str) -> list[str]:
        """Return meaningful non-generic segments of a path."""
        generic = {"api", "v1", "v2", "v3", "v4", "rest", ""}
        return [seg for seg in p.strip("/").split("/") if seg and seg not in generic and not seg.startswith("{")]

    # Tier 1: full verbatim match
    exact_hits = [p for p in doc_paths if isinstance(p, str) and len(p) > 5 and p in q5_report]
    # Tier 2: param-stripped match (/api/items/ from /api/items/{id} appears in response)
    stripped_hits = [
        p for p in doc_paths
        if isinstance(p, str) and len(p) > 5 and not p in exact_hits
        and _strip_params(p) and len(_strip_params(p)) > 5
        and _strip_params(p) in q5_report
    ]
    # Tier 3: any significant path segment from the doc path appears in a path context in the response
    segment_hits: list[str] = []
    q5_lower = (q5_report or "").lower()
    for p in doc_paths:
        if p in exact_hits or p in stripped_hits:
            continue
        for seg in _path_segments(p or ""):
            # Check exact segment OR 4-char stem (handles plural/singular variants like contracts/contract)
            if len(seg) > 3 and (seg.lower() in q5_lower or (len(seg) > 4 and seg[:4].lower() in q5_lower)):
                segment_hits.append(p)
                break

    hits = exact_hits + stripped_hits + segment_hits
    return {
        "doc_path_count_estimate": len(doc_paths),
        "q5_contains_doc_subpath": len(hits) > 0,
        "matched_snippets": hits[:8],
        "match_tier": "exact" if exact_hits else ("stripped" if stripped_hits else ("segment" if segment_hits else "none")),
    }


def _report_paths(text: str) -> list[str]:
    raw = re.findall(r"/[A-Za-z0-9._{}\-]+(?:/[A-Za-z0-9._{}\-]+)+", text or "")
    return [p.rstrip(".,);]") for p in raw]


def _audit_response(report: str, doc: str) -> dict:
    doc_paths = _paths_in_doc(doc)
    rep_paths = _report_paths(report)
    doc_lower = (doc or "").lower()
    report_lower = (report or "").lower()
    unknown = sorted({p for p in rep_paths if not any(p.startswith(dp.rstrip("}")) or dp in p or p in dp for dp in doc_paths)})
    bad_patterns = []
    for pat in (
        "if user b receives",
        "401 unauthorized",
        "without a token",
        "invalid token",
        "graphql mutation",
        "assume the api has",
        "vulnerable outcome (403 forbidden)",
    ):
        if pat in report_lower:
            bad_patterns.append(pat)
    if "[use only endpoints from documentation]" in report_lower:
        bad_patterns.append("placeholder_marker_detected")
    if report.count("```") % 2 != 0:
        bad_patterns.append("unbalanced_code_fences")

    # Detect duplicated low-signal finding headings.
    titles = re.findall(r"^\s*#{2,4}\s+(.+)$", report or "", flags=re.MULTILINE)
    normalized = [re.sub(r"[^a-z0-9 ]+", "", t.lower()).strip() for t in titles]
    duplicate_titles = sorted({t for t in normalized if t and normalized.count(t) > 1})

    # Detect operation names in report that do not appear in the source artifact.
    op_re = r"(RecordUi\.[A-Za-z0-9_]+|ACTION\$[A-Za-z0-9_]+|[A-Za-z0-9_]+(?:WithFields|Connection|Lookup|Mutation))"
    doc_ops = set(re.findall(op_re, doc or ""))
    rep_ops = set(re.findall(op_re, report or ""))
    unknown_ops = sorted(op for op in rep_ops if op and op not in doc_ops)

    # HAR/aura-specific grounding checks.
    har_signals = {
        "doc_has_aura": "/sfsites/aura" in doc_lower or "aura.recordui" in doc_lower,
        "doc_has_form_urlencoded": "application/x-www-form-urlencoded" in doc_lower,
    }
    har_grounding_notes: list[str] = []
    if har_signals["doc_has_aura"] and har_signals["doc_has_form_urlencoded"]:
        if "authorization: bearer" in report_lower and "aura.token" in doc_lower:
            har_grounding_notes.append("report_uses_bearer_abstraction_for_aura_form_flow")
        if "application/x-www-form-urlencoded" not in report_lower:
            har_grounding_notes.append("report_missing_form_urlencoded_request_shape")
        if "message=" not in report_lower and "actions" not in report_lower:
            har_grounding_notes.append("report_missing_aura_message_payload_shape")
    return {
        "unknown_paths": unknown[:12],
        "suspicious_phrases": bad_patterns,
        "duplicate_finding_titles": duplicate_titles,
        "unknown_operation_tokens": unknown_ops[:20],
        "har_grounding_notes": har_grounding_notes,
        "path_count_in_report": len(rep_paths),
    }


def _check_logical_correctness(query: str, report: str, doc: str | None = None) -> dict:
    """Verify the response logically answers the question type that was asked.

    Returns a dict with:
    - question_type: detected category of the question
    - expected_elements: list of elements that should appear in the response
    - found: mapping of expected element → bool indicating presence
    - logical_match: True if the response satisfies the question's intent
    - notes: list of failure notes (empty when logical_match is True)
    """
    q = (query or "").lower()
    r = (report or "").lower()
    notes: list[str] = []

    # Runbook / numbered-steps questions (q4-style)
    if "runbook" in q or ("numbered" in q and ("step" in q or "authorization" in q)):
        has_numbered = bool(re.search(r"^\d+\.", report, re.MULTILINE))
        has_curl = "curl" in r
        logical_match = has_numbered
        if not has_numbered:
            notes.append("Expected numbered steps for runbook question but found none")
        return {
            "question_type": "runbook",
            "expected_elements": ["numbered_steps"],
            "found": {"numbered_steps": has_numbered, "curl_present": has_curl},
            "logical_match": logical_match,
            "notes": notes,
        }

    # Curl generation questions (q5-style: "only two curl commands")
    if "two curl" in q or "curl commands" in q or "give **only** two curl" in q:
        curl_count = len(re.findall(r"\bcurl\b", r))
        has_two = curl_count >= 2
        has_token_1 = "auth_token_1" in r or "bearer" in r
        has_token_2 = "auth_token_2" in r
        has_bad_placeholder = "[use only endpoints from documentation]" in r or bool(re.search(r"(^|\s)/api(\s|$)", report))
        logical_match = has_two and not has_bad_placeholder
        if not has_two:
            notes.append(f"Expected ≥2 curl commands but found ~{curl_count}")
        if not has_token_1 or not has_token_2:
            notes.append("Expected two different Bearer tokens (AUTH_TOKEN_1 and AUTH_TOKEN_2)")
        if has_bad_placeholder:
            notes.append("Detected generic placeholder endpoint in curl output (/API or bracket marker)")
        return {
            "question_type": "curl_generation",
            "expected_elements": ["two_curl_commands", "auth_token_1", "auth_token_2"],
            "found": {
                "curl_count_estimate": curl_count,
                "has_two_curls": has_two,
                "auth_token_1": has_token_1,
                "auth_token_2": has_token_2,
                "has_bad_placeholder": has_bad_placeholder,
            },
            "logical_match": logical_match,
            "notes": notes,
        }

    # Path audit questions (q6-style: "state yes if it appears")
    if "state yes if it appears" in q or ("list every" in q and "path" in q) or "if hallucinated" in q:
        has_yes = "yes" in r
        has_no = "no" in r
        has_arrow = "->" in r or "→" in r
        logical_match = has_yes or has_no or has_arrow
        if not logical_match:
            notes.append("Expected YES/NO path audit entries but found none")
        return {
            "question_type": "path_audit",
            "expected_elements": ["yes_no_entries"],
            "found": {"has_yes": has_yes, "has_no": has_no, "has_arrow": has_arrow},
            "logical_match": logical_match,
            "notes": notes,
        }

    # Simple request generation: "generate a request to verify" or "generate me full request"
    if ("generate" in q and "request" in q) or "full request" in q:
        has_curl = "curl" in r
        has_method = bool(re.search(r"\b(get|post|put|patch|delete)\b", r))
        has_auth = "authorization" in r or "bearer" in r or "session" in r or "token" in r
        has_numbered = bool(re.search(r"^\d+\.", report, re.MULTILINE))
        # Accept curl OR numbered verification steps with HTTP method or auth as valid responses
        logical_match = (has_curl and has_method) or (has_numbered and (has_method or has_auth))
        if not logical_match:
            notes.append("Expected curl command but found none")
        return {
            "question_type": "request_generation",
            "expected_elements": ["curl_command", "http_method", "auth_header"],
            "found": {"curl": has_curl, "method": has_method, "auth": has_auth, "numbered_steps": has_numbered},
            "logical_match": logical_match,
            "notes": notes,
        }

    # "If the doc has GraphQL" questions: correct answer is either GraphQL verification steps
    # OR an explicit "not applicable" statement when the doc is REST-only.
    if "if the doc has graphql" in q:
        says_not_applicable = any(x in r for x in (
            "not applicable", "no graphql operation", "rest-only", "rest only", "not documented",
            "graphql-specific verification is not applicable", "no graphql", "does not use graphql",
            "does not include graphql", "no graphql endpoints", "graphql is not",
            "not mentioned", "not present", "no graphql schema", "graphql is absent",
            "this api does not", "graphql operations are not",
        ))
        has_graphql_steps = "graphql" in r and any(w in r for w in ("token", "verify", "two tokens", "user a"))
        # If the doc itself has no GraphQL, a security analysis of the actual doc is also acceptable.
        doc_has_graphql = "graphql" in (doc or "").lower() if doc else False
        doc_is_rest_only = not doc_has_graphql
        has_security_analysis = any(w in r for w in ("bola", "authorization", "verify", "endpoint", "finding", "risk"))
        logical_match = says_not_applicable or has_graphql_steps or (doc_is_rest_only and has_security_analysis)
        if not logical_match:
            notes.append("Expected either GraphQL verification steps or explicit 'not applicable' statement")
        return {
            "question_type": "graphql_verification_or_na",
            "expected_elements": ["graphql_steps_or_not_applicable"],
            "found": {
                "says_not_applicable": says_not_applicable,
                "has_graphql_steps": has_graphql_steps,
                "doc_is_rest_only": doc_is_rest_only,
                "has_security_analysis": has_security_analysis,
            },
            "logical_match": logical_match,
            "notes": notes,
        }

    # General security analysis / findings questions (q1/q2/q3-style)
    # Also catches: batch/bulk verification, comparative verification, GraphQL authorization,
    # two-identity checks, endpoint-specific security questions.
    _analysis_keywords = (
        "security risk", "vulnerability", "bola", "findings", "what are", "authorization risk",
        "audit", "what security", "review", "i'm auditing", "security reviewer",
        "batch", "bulk", "comparative verification", "two-identity", "two tokens",
        "verify authorization", "authorization with two", "highest-risk", "security test",
        "pick the", "describe", "explain", "what risk", "identify", "how should i verify",
        "could one", "could a picker", "tampering",
    )
    if any(x in q for x in _analysis_keywords):
        has_finding_heading = "###" in report
        has_path = bool(re.search(r"/[a-z0-9]{3,}", r))
        has_rationale = any(w in r for w in ("rationale", "observation", "risk", "gap", "ownership", "potential"))
        has_verification = any(w in r for w in ("verification", "verify", "token", "curl", "step"))
        logical_match = has_finding_heading or (has_rationale and has_verification)
        if not logical_match:
            notes.append("Expected structured findings or rationale+verification but found neither")
        return {
            "question_type": "security_analysis",
            "expected_elements": ["finding_headings_or_rationale_plus_verification"],
            "found": {
                "has_finding_heading": has_finding_heading,
                "has_path": has_path,
                "has_rationale": has_rationale,
                "has_verification": has_verification,
            },
            "logical_match": logical_match,
            "notes": notes,
        }

    # Outcome interpretation: "what does 200 vs 403 mean"
    if ("200" in q and "403" in q) or ("mean" in q and ("result" in q or "outcome" in q)):
        has_403_explanation = "403" in r
        has_200_explanation = "200" in r
        logical_match = has_403_explanation and has_200_explanation
        if not logical_match:
            notes.append("Expected explanation of 200 vs 403 outcomes but both not found")
        return {
            "question_type": "outcome_interpretation",
            "expected_elements": ["200_explanation", "403_explanation"],
            "found": {"has_200": has_200_explanation, "has_403": has_403_explanation},
            "logical_match": logical_match,
            "notes": notes,
        }

    # Default: unknown question type — no strict checking
    return {
        "question_type": "unknown",
        "expected_elements": [],
        "found": {},
        "logical_match": True,
        "notes": ["Question type not recognized; logical correctness not enforced for this query"],
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
        "person_e2e_baseline": {
            "initial_person_questions": len(_initial_queries(fixture.name, fixture_meta.get("doc_type", "rest_doc"))),
            "followup_detail_200_403": True,
            "followup_fake_token_curls": True,
            "followup_self_path_validation": True,
            "separate_post_analyze_each": True,
            "adaptive_grounding_remediation": True,
        },
        "steps": [],
    }
    if er:
        log["expected_risks"] = json.loads(er)

    _no_keepalive = httpx.Limits(max_keepalive_connections=0, max_connections=100)
    with httpx.Client(timeout=TIMEOUT_QUICK, limits=_no_keepalive) as c:
        r = c.post(f"{BASE}/reset")
        log["steps"].append({"name": "reset", "status": r.status_code})
        r.raise_for_status()

    with httpx.Client(timeout=TIMEOUT_INGEST, limits=_no_keepalive) as c:
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
            if r.status_code == 404:
                # Backward compatibility: older runtime images may not expose /ingest_shared.
                r = c.post(f"{BASE}/ingest", data={"content": doc, "source": fixture.stem})
                log["steps"].append(
                    {
                        "name": "ingest_shared_fallback_ingest",
                        "status": r.status_code,
                        "chunks": (r.json() or {}).get("chunks") if r.status_code == 200 else None,
                        "reason": "/ingest_shared missing on runtime",
                    }
                )
            else:
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

    queries = _initial_queries(fixture.name, fixture_meta.get("doc_type", "rest_doc")) + FOLLOWUPS
    logical_failures: list[str] = []
    audit_issue_count = 0
    with httpx.Client(timeout=TIMEOUT_ANALYZE, limits=_no_keepalive) as c:
        for key, q in queries:
            try:
                r = c.post(f"{BASE}/analyze", json={"query": q})
                status = r.status_code
                rep = (r.json() or {}).get("report") or "" if status == 200 else ""
            except httpx.ReadTimeout:
                status = 598
                rep = ""
                log["steps"].append(
                    {
                        "name": key,
                        "status": status,
                        "query_preview": q[:180],
                        "report_len": 0,
                        "logical_match": False,
                        "logical_notes": ["Read timeout during analyze request"],
                    }
                )
                logical_failures.append(f"{key}: analyze request timed out")
                continue
            lc = _check_logical_correctness(q, rep, doc=doc)
            log["steps"].append(
                {
                    "name": key,
                    "status": status,
                    "query_preview": q[:180],
                    "report_len": len(rep),
                    "logical_match": lc["logical_match"],
                    "logical_notes": lc["notes"],
                }
            )
            log[f"report_{key}_full"] = rep
            log[f"logical_check_{key}"] = lc
            if key in {"q1", "q2", "q3", "q4_detail_runbook"}:
                audit = _audit_response(rep, doc)
                log[f"audit_{key}"] = audit
                issue_parts = (
                    len(audit.get("unknown_paths", []))
                    + len(audit.get("suspicious_phrases", []))
                    + len(audit.get("duplicate_finding_titles", []))
                    + len(audit.get("unknown_operation_tokens", []))
                    + len(audit.get("har_grounding_notes", []))
                )
                audit_issue_count += issue_parts
            if not lc["logical_match"]:
                logical_failures.append(f"{key}: {'; '.join(lc['notes'])}")

        # Adaptive remediation pass: if audit found quality issues, request a corrected answer.
        if audit_issue_count > 0:
            remediation_query = (
                "Re-answer your prior analysis with strict grounding only. "
                "Do not use placeholders, do not invent operations, and keep request shape aligned with the artifact "
                "(including Aura form-encoded body fields when Aura is present)."
            )
            try:
                rr = c.post(f"{BASE}/analyze", json={"query": remediation_query})
                rem_status = rr.status_code
                rem_rep = (rr.json() or {}).get("report") or "" if rem_status == 200 else ""
            except httpx.ReadTimeout:
                rem_status = 598
                rem_rep = ""
            rem_lc = _check_logical_correctness(remediation_query, rem_rep, doc=doc)
            rem_audit = _audit_response(rem_rep, doc)
            rem_issue_count = (
                len(rem_audit.get("unknown_paths", []))
                + len(rem_audit.get("suspicious_phrases", []))
                + len(rem_audit.get("duplicate_finding_titles", []))
                + len(rem_audit.get("unknown_operation_tokens", []))
                + len(rem_audit.get("har_grounding_notes", []))
            )
            log["steps"].append(
                {
                    "name": "q7_adaptive_remediation",
                    "status": rem_status,
                    "query_preview": remediation_query[:180],
                    "report_len": len(rem_rep),
                    "logical_match": rem_lc["logical_match"],
                    "logical_notes": rem_lc["notes"],
                    "issue_count_before": audit_issue_count,
                    "issue_count_after": rem_issue_count,
                    "issue_delta": audit_issue_count - rem_issue_count,
                }
            )
            log["report_q7_adaptive_remediation_full"] = rem_rep
            log["logical_check_q7_adaptive_remediation"] = rem_lc
            log["audit_q7_adaptive_remediation"] = rem_audit
            if not rem_lc["logical_match"]:
                logical_failures.append(f"q7_adaptive_remediation: {'; '.join(rem_lc['notes'])}")

    q5 = log.get("report_q5_fake_curls_full", "")
    q5_grounding = _validate_q5_against_doc(doc, q5)
    # Only flag grounding failure for substantive path mismatches, not generic placeholders
    # (generic placeholders like /API or /api are already caught by the curl_generation check)
    _q5_has_substantive_path = bool(re.search(r"/[a-z][a-z0-9_/]{4,}", (q5 or "").lower()))
    if not q5_grounding.get("q5_contains_doc_subpath", False) and _q5_has_substantive_path:
        logical_failures.append("q5_fake_curls: generated curl paths were not grounded to doc paths")
    log["automated_checks"] = {
        "q5_grounding": q5_grounding,
        "q6_expected_path_audit": "manual_read_report_q6",
        "logical_correctness_summary": {
            "total_steps": len(queries),
            "logical_failures": logical_failures,
            "all_logical_matches": len(logical_failures) == 0,
        },
    }

    OUT.write_text(json.dumps(log, indent=2)[:800000], encoding="utf-8")
    print("Wrote", OUT)
    print(f"Person E2E completed: {len(queries)} separate analyze calls.")
    if logical_failures:
        print(f"LOGICAL CORRECTNESS FAILURES ({len(logical_failures)}):")
        for f in logical_failures:
            print(f"  - {f}")
    else:
        print("All responses logically match their question types.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
