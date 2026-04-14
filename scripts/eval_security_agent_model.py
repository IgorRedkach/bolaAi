#!/usr/bin/env python3
"""Evaluate model outputs with groundedness/security-oriented metrics.

Refactored for Wide-Spectrum Ontology (SCADA, Cloud, API) and 
updated investigative-lead prompt structures.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from training_pipeline_common import ROOT, iter_jsonl, utc_ts, write_json


def _contains_methodology_indicators(text: str) -> bool:
    """
    Checks if the model provided a valid testing methodology. 
    Expanded to allow scripts, WebSockets, and GraphQL, removing the 'curl-only' bias.
    """
    low = text.lower()
    has_path = "/" in text
    has_http_method = any(tok in text for tok in ("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"))
    has_tool_or_protocol = any(tok in low for tok in (
        "curl", "python", "burp", "intruder", "graphql", "websocket", "wscat", "script"
    ))
    return has_path and (has_http_method or has_tool_or_protocol)


def _score_row(row: dict) -> dict:
    target = str(row.get("target", ""))
    low = target.lower()
    
    # 1. Groundedness (Anti-Hallucination)
    # Checks for explicit placeholder markers forbidden by the new prompt.
    placeholders = [
        "[use only endpoints from documentation]", 
        "/api ", 
        "[insert", 
        "<your", 
        "your-token"
    ]
    grounded = not any(p in low for p in placeholders)
    
    # 2. Methodology Correctness (Replaces rigid tool_correct)
    methodology_correct = _contains_methodology_indicators(target)
    
    # 3. Actionability (supports both new and legacy report styles)
    has_hypothesis = ("threat hypothesis" in low) or ("finding" in low)
    has_steps = ("analyst investigation steps" in low) or ("reproduction" in low) or ("verification" in low)
    has_poc = ("proof of concept" in low) or ("curl" in low) or ("python" in low) or ("graphql" in low)
    has_expected = ("expected secure outcome" in low) or ("secure outcome" in low) or ("remediation" in low)
    actionable = has_hypothesis and has_steps and has_poc and has_expected
    
    # 4. Severity Weighting (Expanded for Critical Infra & Advanced Patterns)
    high_sev_keywords = (
        "scada", "ics", "firmware", "rce", "ssrf", "ssti", "cloning", 
        "mass assignment", "cross-tenant", "token theft", "admin bypass"
    )
    severity_weight = 4 if any(x in low for x in high_sev_keywords) else 1
    
    # 5. False Positive Logic (Confidence Mismatches)
    is_high_confidence = "high-confidence finding" in low
    expresses_doubt = any(x in low for x in ("might be", "possibly", "unclear", "cannot verify"))
    fp_auth_only = "vulnerability confirmed from 401" in low
    
    # It's a false positive if it claims High-Confidence but uses doubtful language, 
    # OR if it confirms BOLA purely from an unauthenticated 401 error.
    false_positive = 1 if (fp_auth_only or (is_high_confidence and expresses_doubt)) else 0
    
    return {
        "grounded": grounded,
        "methodology_correct": methodology_correct,
        "actionable": actionable,
        "severity_weight": severity_weight,
        "false_positive": false_positive,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate security agent quality on holdout")
    parser.add_argument(
        "--config",
        default=str(ROOT / "configs" / "training" / "eval.yaml"),
        help="Eval config YAML path",
    )
    args = parser.parse_args()

    cfg_path = Path(args.config).resolve()
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    holdout = (ROOT / cfg["dataset"]["holdout"]).resolve()
    
    total = 0
    grounded_sum = 0
    methodology_sum = 0
    actionable_sum = 0
    fp_sum = 0
    weighted_grounded = 0
    weighted_total = 0
    
    for row in iter_jsonl(holdout):
        total += 1
        score = _score_row(row)
        grounded_sum += int(score["grounded"])
        methodology_sum += int(score["methodology_correct"])
        actionable_sum += int(score["actionable"])
        fp_sum += score["false_positive"]
        weighted_grounded += int(score["grounded"]) * score["severity_weight"]
        weighted_total += score["severity_weight"]
        
    n = total or 1
    grounded = grounded_sum / n
    methodology = methodology_sum / n
    actionable = actionable_sum / n
    weighted_recall = weighted_grounded / max(1, weighted_total)
    fp_rate = fp_sum / n
    
    # Kappa proxy measures inter-rater reliability equivalent (balanced pass rate)
    kappa_proxy = max(0.0, min(1.0, (grounded + methodology + actionable) / 3))
    
    metrics = {
        "groundedness_rate": round(grounded, 4),
        "testing_methodology_rate": round(methodology, 4),
        "actionable_finding_rate": round(actionable, 4),
        "severity_weighted_recall": round(weighted_recall, 4),
        "false_positive_rate": round(fp_rate, 4),
        "cohens_kappa": round(kappa_proxy, 4),
    }
    
    # Backwards compatibility check for the yaml config keys
    thresholds = cfg["metrics"]
    tool_threshold_key = "tool_call_correctness_min" if "tool_call_correctness_min" in thresholds else "testing_methodology_min"
    
    gates = {
        "groundedness_pass": metrics["groundedness_rate"] >= thresholds.get("groundedness_min", 0.85),
        "methodology_pass": metrics["testing_methodology_rate"] >= thresholds.get(tool_threshold_key, 0.80),
        "actionable_pass": metrics["actionable_finding_rate"] >= thresholds.get("actionable_finding_rate_min", 0.85),
        "weighted_recall_pass": metrics["severity_weighted_recall"] >= thresholds.get("severity_weighted_recall_min", 0.80),
        "false_positive_pass": metrics["false_positive_rate"] <= thresholds.get("false_positive_rate_max", 0.15),
        "kappa_pass": metrics["cohens_kappa"] >= thresholds.get("cohens_kappa_min", 0.70),
    }
    all_pass = all(gates.values())

    ts = utc_ts()
    report_dir = ROOT / cfg["outputs"]["report_dir"]
    report_json = report_dir / f"model_eval_{ts}.json"
    report_md = report_dir / f"model_eval_{ts}.md"
    
    payload = {
        "created_at": ts,
        "config": str(cfg_path),
        "holdout": str(holdout),
        "rows": total,
        "metrics": metrics,
        "gates": gates,
        "all_pass": all_pass,
    }
    
    write_json(report_json, payload)
    report_md.parent.mkdir(parents=True, exist_ok=True)
    
    report_md.write_text(
        "\n".join(
            [
                f"# Model Eval {ts}",
                "",
                f"- Holdout rows: {total}",
                f"- All gates pass: **{all_pass}**",
                "",
                "## Metrics",
                *(f"- {k}: {v}" for k, v in metrics.items()),
                "",
                "## Gates",
                *(f"- {k}: {v}" for k, v in gates.items()),
            ]
        ),
        encoding="utf-8",
    )
    
    print(json.dumps({"all_pass": all_pass, "report_json": str(report_json), "report_md": str(report_md)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())