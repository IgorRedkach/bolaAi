#!/usr/bin/env python3
"""
Self-comparison test: for each fixture, independently generate the agent's
own best security analysis, then compare against the live tool's response.
Save structured comparison results to docs/self_comparison_results/.

Methodology:
1. Read the fixture doc.
2. Call the live tool's /analyze endpoint → tool_response.
3. Call the Ollama model directly with the same prompt + doc → self_response.
4. Compare on structured dimensions; classify discrepancies by severity.
5. Save results. Exit 1 if CRITICAL discrepancies exceed threshold.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "self_comparison_results"
OUT_DIR.mkdir(parents=True, exist_ok=True)

FIXTURES_DIR = ROOT / "tests" / "fixtures"
OLLAMA_URL = "http://localhost:11434"
BOLA_API_URL = "http://localhost:8000"
MODEL = "bola-analyzer"

COMPARISON_QUERY = (
    "As a security reviewer reading this API documentation only: "
    "identify all authorization gaps (BOLA, BAC, injection, misconfiguration, logging failures, "
    "exceptional conditions). For each finding: state the evidence chain, vulnerability class, "
    "verification steps, and how the finding was identified."
)

SELF_ANALYSIS_SYSTEM = (
    "You are an expert application security analyst. "
    "Analyze the provided artifact independently. "
    "For each finding provide: title, evidence citations (grounded to artifact), "
    "vulnerability class (from bola_patterns.md taxonomy), "
    "verification steps using single-token ID-swap methodology for BOLA, "
    "and a 'How This Finding Was Identified' section explaining the chain of evidence. "
    "Do NOT use 'User A / User B' framing. "
    "Use only paths and operations that appear in the provided artifact text."
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _call_tool(base_url: str, doc_text: str, timeout: float = 300.0) -> str:
    """Ingest doc into the tool and call /analyze."""
    no_keepalive = httpx.Limits(max_keepalive_connections=0, max_connections=20)
    with httpx.Client(timeout=30.0, limits=no_keepalive) as c:
        c.post(f"{base_url}/reset", timeout=30.0)
    with httpx.Client(timeout=120.0, limits=no_keepalive) as c:
        r = c.post(
            f"{base_url}/ingest",
            files={"content": (None, doc_text)},
            data={"source": "self_comparison_test"},
            timeout=120.0,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Ingest failed: {r.status_code} {r.text[:200]}")
    with httpx.Client(timeout=timeout, limits=no_keepalive) as c:
        r = c.post(f"{base_url}/analyze", json={"query": COMPARISON_QUERY}, timeout=timeout)
        if r.status_code != 200:
            raise RuntimeError(f"Analyze failed: {r.status_code} {r.text[:200]}")
        return (r.json() or {}).get("report", "")


def _call_self(ollama_url: str, doc_text: str, timeout: float = 300.0) -> str:
    """Call the Ollama model directly to generate the agent's own analysis."""
    prompt = (
        f"{SELF_ANALYSIS_SYSTEM}\n\n"
        f"Artifact to analyze:\n\n{doc_text}\n\n"
        f"Query: {COMPARISON_QUERY}"
    )
    no_keepalive = httpx.Limits(max_keepalive_connections=0, max_connections=20)
    with httpx.Client(timeout=timeout, limits=no_keepalive) as c:
        r = c.post(
            f"{ollama_url}/api/generate",
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.1, "num_predict": 2048},
            },
            timeout=timeout,
        )
        if r.status_code != 200:
            raise RuntimeError(f"Ollama call failed: {r.status_code} {r.text[:200]}")
        return (r.json() or {}).get("response", "")


def _extract_paths(text: str) -> list[str]:
    return re.findall(r"/[a-zA-Z][a-zA-Z0-9_/{}?=-]{4,}", text)


def _extract_finding_titles(text: str) -> list[str]:
    return re.findall(r"###\s+(.+)", text)


def _compare(tool: str, self_: str, doc: str) -> dict:
    """Compare tool vs self-generated responses across structured dimensions."""
    discrepancies: list[dict] = []

    t_lower = tool.lower()
    s_lower = self_.lower()
    d_lower = doc.lower()

    # Dimension 1: finding count
    t_findings = len(_extract_finding_titles(tool))
    s_findings = len(_extract_finding_titles(self_))
    if t_findings == 0 and s_findings > 0:
        discrepancies.append({
            "dimension": "finding_count",
            "severity": "CRITICAL",
            "detail": f"Tool produced 0 finding headings; self-analysis found {s_findings}.",
            "improvement": "Check if the tool's prompt is too restrictive or if the model failed to produce structured output.",
        })
    elif abs(t_findings - s_findings) >= 2:
        discrepancies.append({
            "dimension": "finding_count",
            "severity": "MAJOR",
            "detail": f"Tool: {t_findings} findings; self: {s_findings} findings — difference ≥ 2.",
            "improvement": "Review which findings were missed; add examples to training data covering those pattern types.",
        })

    # Dimension 2: path grounding
    doc_paths = set(_extract_paths(doc))
    t_paths = set(_extract_paths(tool))
    s_paths = set(_extract_paths(self_))
    t_hallucinated = [p for p in t_paths if p not in doc_paths and len(p) > 8]
    s_hallucinated = [p for p in s_paths if p not in doc_paths and len(p) > 8]
    if t_hallucinated:
        discrepancies.append({
            "dimension": "path_grounding",
            "severity": "CRITICAL",
            "detail": f"Tool hallucinated paths not in doc: {t_hallucinated[:5]}",
            "improvement": "Strengthen grounding instructions in the Modelfile system prompt.",
        })
    if s_hallucinated:
        discrepancies.append({
            "dimension": "path_grounding",
            "severity": "MAJOR",
            "detail": f"Self-analysis hallucinated paths: {s_hallucinated[:5]}",
            "improvement": "Self-analysis model also tends to hallucinate paths — this is a training data grounding issue.",
        })

    # Dimension 3: verification quality
    t_has_verif = "verification" in t_lower or "verify" in t_lower
    s_has_verif = "verification" in s_lower or "verify" in s_lower
    if t_has_verif and not s_has_verif:
        discrepancies.append({
            "dimension": "verification_quality",
            "severity": "MAJOR",
            "detail": "Tool has verification steps; self-analysis does not.",
            "improvement": "Self-analysis prompt may need stronger instruction to include verification steps.",
        })
    elif not t_has_verif and s_has_verif:
        discrepancies.append({
            "dimension": "verification_quality",
            "severity": "MAJOR",
            "detail": "Self-analysis has verification steps; tool does not.",
            "improvement": "Tool Modelfile system prompt should require verification steps more explicitly.",
        })

    # Dimension 4: chain of evidence
    t_has_chain = "how this finding" in t_lower or "chain of evidence" in t_lower or "identified" in t_lower
    s_has_chain = "how this finding" in s_lower or "chain of evidence" in s_lower
    if s_has_chain and not t_has_chain:
        discrepancies.append({
            "dimension": "chain_of_evidence",
            "severity": "MAJOR",
            "detail": "Self-analysis includes 'How This Finding Was Identified'; tool does not.",
            "improvement": "Add '## How This Finding Was Identified' requirement to the training data expected responses.",
        })

    # Dimension 5: classification accuracy
    t_has_bola = "bola" in t_lower
    s_has_bola = "bola" in s_lower
    t_has_bac = "broken access control" in t_lower or " bac " in t_lower
    s_has_bac = "broken access control" in s_lower or " bac " in s_lower
    if s_has_bola and not t_has_bola:
        discrepancies.append({
            "dimension": "classification_accuracy",
            "severity": "CRITICAL",
            "detail": "Self-analysis identified BOLA; tool did not mention BOLA.",
            "improvement": "Add training examples that explicitly label BOLA findings for this artifact type.",
        })

    # Dimension 6: User A/B framing (should be absent)
    user_ab_pattern = re.compile(r"\buser [ab]\b|\btoken [ab]\b", re.IGNORECASE)
    t_user_ab = bool(user_ab_pattern.search(tool))
    if t_user_ab:
        discrepancies.append({
            "dimension": "methodology",
            "severity": "MINOR",
            "detail": "Tool response uses 'User A/B' or 'Token A/B' framing.",
            "improvement": "Update Modelfile and training examples to use single-token ID-swap methodology.",
        })

    critical = sum(1 for d in discrepancies if d["severity"] == "CRITICAL")
    major = sum(1 for d in discrepancies if d["severity"] == "MAJOR")
    minor = sum(1 for d in discrepancies if d["severity"] == "MINOR")

    return {
        "tool_finding_count": t_findings,
        "self_finding_count": s_findings,
        "discrepancy_count": len(discrepancies),
        "critical": critical,
        "major": major,
        "minor": minor,
        "discrepancies": discrepancies,
    }


def run_comparison(fixture: Path, base_url: str, ollama_url: str, timeout: float) -> dict:
    doc_text = fixture.read_text(encoding="utf-8")
    print(f"  Calling tool ({base_url}) ...")
    tool_response = _call_tool(base_url, doc_text, timeout=timeout)
    print(f"  Calling self ({ollama_url}) ...")
    self_response = _call_self(ollama_url, doc_text, timeout=timeout)
    comparison = _compare(tool_response, self_response, doc_text)
    result = {
        "fixture": str(fixture),
        "timestamp": _utc_now(),
        "tool_response": tool_response,
        "self_response": self_response,
        "comparison": comparison,
    }
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="Run self-comparison test for one or all fixtures")
    ap.add_argument("--fixture", default=None, help="Path to a single fixture file (default: all)")
    ap.add_argument("--base-url", default=BOLA_API_URL)
    ap.add_argument("--ollama-url", default=OLLAMA_URL)
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument(
        "--max-critical",
        type=int,
        default=3,
        help="Maximum CRITICAL discrepancies before exit code 1",
    )
    args = ap.parse_args()

    if args.fixture:
        fixtures = [Path(args.fixture).resolve()]
    else:
        fixtures = sorted(FIXTURES_DIR.glob("*.md"))[:5]  # default: first 5

    all_results: list[dict] = []
    total_critical = 0

    for fix in fixtures:
        print(f"\n=== {fix.name} ===")
        try:
            result = run_comparison(fix, args.base_url, args.ollama_url, args.timeout)
        except Exception as e:
            print(f"  ERROR: {e}")
            result = {"fixture": str(fix), "error": str(e), "timestamp": _utc_now()}
        all_results.append(result)
        cmp = result.get("comparison", {})
        total_critical += cmp.get("critical", 0)
        print(
            f"  Findings: tool={cmp.get('tool_finding_count','?')} self={cmp.get('self_finding_count','?')}"
        )
        print(
            f"  Discrepancies: critical={cmp.get('critical',0)} major={cmp.get('major',0)} minor={cmp.get('minor',0)}"
        )
        for d in cmp.get("discrepancies", []):
            print(f"    [{d['severity']}] {d['dimension']}: {d['detail'][:100]}")

    # Save results
    ts = _utc_now().replace(":", "").replace("-", "")[:15]
    out_path = OUT_DIR / f"comparison_{ts}.json"
    out_path.write_text(json.dumps(all_results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved comparison results to: {out_path}")

    # Generate improvement recommendations
    recommendations: list[str] = []
    for result in all_results:
        for d in result.get("comparison", {}).get("discrepancies", []):
            if d.get("improvement") and d["severity"] in ("CRITICAL", "MAJOR"):
                recommendations.append(f"[{d['severity']}] {d['dimension']}: {d['improvement']}")

    if recommendations:
        rec_path = ROOT / "docs" / "training_improvement_recommendations.md"
        content = (
            "# Training Improvement Recommendations\n\n"
            f"Generated: {_utc_now()}\n"
            f"Fixture count: {len(all_results)}\n"
            f"Total critical discrepancies: {total_critical}\n\n"
            "## Recommendations\n\n"
            + "\n".join(f"- {r}" for r in sorted(set(recommendations)))
            + "\n\n## Next Steps\n\n"
            "1. For CRITICAL grounding issues: strengthen `Modelfile` system prompt grounding rules.\n"
            "2. For CRITICAL missing findings: add training examples for those pattern types.\n"
            "3. For MAJOR chain-of-evidence gaps: add '## How This Finding Was Identified' "
            "to all training example targets.\n"
            "4. For MAJOR verification gaps: update `EXPECTED_RESPONSE_PROMPT` in `ai_teacher_prompts.py`.\n"
            "5. Re-run `generate_data.py --clean` and then retrain.\n"
        )
        rec_path.write_text(content, encoding="utf-8")
        print(f"Saved recommendations to: {rec_path}")

    if total_critical > args.max_critical:
        print(f"\nFAIL: {total_critical} critical discrepancies (threshold: {args.max_critical})")
        return 1
    print(f"\nPASS: {total_critical} critical discrepancies (threshold: {args.max_critical})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
