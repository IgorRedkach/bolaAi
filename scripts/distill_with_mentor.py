#!/usr/bin/env python3
"""Mentor-pass distillation to simplify rationale traces for small models."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from training_pipeline_common import TRAINING_DIR, ensure_dir, iter_jsonl, utc_ts, write_json


def _mentor_compact(text: str, max_len: int) -> str:
    text = " ".join(part.strip() for part in text.splitlines() if part.strip())
    text = text.replace("**", "")
    replacements = [
        ("Potential findings", "Findings"),
        ("Verification steps", "Verify"),
        ("Vulnerable outcome", "Vuln"),
        ("Secure outcome", "Secure"),
    ]
    for old, new in replacements:
        text = text.replace(old, new)
    return text[:max_len].strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply mentor simplification to distilled rows")
    parser.add_argument(
        "--input",
        default=str(TRAINING_DIR / "distilled" / "teacher_distilled.jsonl"),
        help="Input distilled JSONL",
    )
    parser.add_argument(
        "--output",
        default=str(TRAINING_DIR / "distilled" / "mentor_distilled.jsonl"),
        help="Output mentor-distilled JSONL",
    )
    parser.add_argument("--max-len", type=int, default=320)
    parser.add_argument("--mentor-name", default="mid-size-mentor")
    args = parser.parse_args()

    out = Path(args.output).resolve()
    src = Path(args.input).resolve()
    ensure_dir(out.parent)
    count = 0
    with out.open("w", encoding="utf-8") as f:
        for row in iter_jsonl(src):
            inst = str(row.get("instruction", "")).strip()
            ctx = str(row.get("context", "")).strip()
            tgt = str(row.get("target", "")).strip()
            explanation = str(row.get("analysis_explanation", "")).strip()
            if not inst or not ctx or not tgt:
                continue
            out_row = {
                "instruction": inst,
                "context": ctx,
                "target": _mentor_compact(tgt, args.max_len),
                "distilled_from": "mentor_pass",
                "mentor_name": args.mentor_name,
                "analysis_explanation": explanation,
            }
            f.write(json.dumps(out_row, ensure_ascii=False) + "\n")
            count += 1
    write_json(
        TRAINING_DIR / "distilled" / "mentor_distilled_manifest.json",
        {
            "created_at": utc_ts(),
            "input": str(src),
            "output": str(out),
            "mentor_name": args.mentor_name,
            "count": count,
        },
    )
    print(f"Wrote {out} ({count} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

