#!/usr/bin/env python3
"""Create compact rationale records from training rows."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from training_pipeline_common import TRAINING_DIR, ensure_dir, iter_jsonl, utc_ts, write_json


def _first_sentence(text: str) -> str:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return parts[0].strip() if parts and parts[0].strip() else text.strip()


def _compact_target(target: str, max_len: int) -> str:
    lines = [ln.strip() for ln in target.splitlines() if ln.strip()]
    risk_line = next((ln for ln in lines if ln.lower().startswith(("risk:", "observation:"))), "")
    ver_line = next((ln for ln in lines if ln.lower().startswith("verification:")), "")
    compact = []
    if risk_line:
        compact.append(risk_line)
    if ver_line:
        compact.append(ver_line)
    if not compact and lines:
        compact.append(_first_sentence(lines[0]))
    out = " ".join(compact).strip()
    return out[:max_len]


def _normalize_row(row: dict) -> tuple[str, str, str, str]:
    context_path = str(row.get("context_path", "")).strip()
    expected_response_path = str(row.get("expected_response_path", "")).strip()
    analysis_explanation_path = str(row.get("analysis_explanation_path", "")).strip()
    if context_path and expected_response_path and analysis_explanation_path:
        cp = Path(context_path)
        rp = Path(expected_response_path)
        ep = Path(analysis_explanation_path)
        if cp.is_file() and rp.is_file() and ep.is_file():
            context = cp.read_text(encoding="utf-8")
            expected_response = rp.read_text(encoding="utf-8").strip()
            analysis_explanation = ep.read_text(encoding="utf-8").strip()
            instruction = "Analyze the artifact context and provide a grounded security response."
            target = f"{expected_response}\n\n## Analysis Explanation\n{analysis_explanation}"
            return instruction, context, target, analysis_explanation

    instruction = str(row.get("instruction", "")).strip()
    context = str(row.get("context", "")).strip()
    target = str(row.get("target", "")).strip()
    analysis_explanation = str(row.get("analysis_explanation", "")).strip()

    if instruction and context and target:
        return instruction, context, target, analysis_explanation

    artifacts_context = str(row.get("artifacts_context", "")).strip()
    expected_response = str(row.get("expected_response", "")).strip()
    if artifacts_context and expected_response:
        instruction = "Analyze the artifact context and provide a grounded security response."
        context = artifacts_context
        if analysis_explanation:
            target = f"{expected_response}\n\n## Analysis Explanation\n{analysis_explanation}"
        else:
            target = expected_response
        return instruction, context, target, analysis_explanation
    return "", "", "", ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Distill verbose training targets into compact forms")
    parser.add_argument("--input", default=str(TRAINING_DIR / "bola_training.jsonl"))
    parser.add_argument("--output", default=str(TRAINING_DIR / "distilled" / "teacher_distilled.jsonl"))
    parser.add_argument("--max-len", type=int, default=420)
    args = parser.parse_args()

    out = Path(args.output).resolve()
    src = Path(args.input).resolve()
    ensure_dir(out.parent)
    count = 0
    with out.open("w", encoding="utf-8") as f:
        for row in iter_jsonl(src):
            instruction, context, target, analysis_explanation = _normalize_row(row)
            if not instruction or not context or not target:
                continue
            out_row = {
                "instruction": instruction,
                "context": context,
                "target": _compact_target(target, args.max_len),
                "distilled_from": "teacher_style",
                "analysis_explanation": analysis_explanation,
            }
            f.write(json.dumps(out_row, ensure_ascii=False) + "\n")
            count += 1
    write_json(
        TRAINING_DIR / "distilled" / "teacher_distilled_manifest.json",
        {"created_at": utc_ts(), "input": str(src), "output": str(out), "count": count},
    )
    print(f"Wrote {out} ({count} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

