#!/usr/bin/env python3
"""Combine all available training data sources into a single manifest JSONL.

Sources combined:
1. All reviewing/ folder records (path-based manifest rows)
2. Accepted AI teaching cycle rows (converted to new schema)
3. Any inline JSONL rows from bola_training.jsonl

Output: data/training/reviewing_training_combined.jsonl
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
TRAINING_DIR = ROOT / "data" / "training"
REVIEWING_DIR = TRAINING_DIR / "reviewing"
AI_CYCLES_DIR = TRAINING_DIR / "ai_cycles"
OUTPUT_PATH = TRAINING_DIR / "reviewing_training_combined.jsonl"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def main() -> int:
    rows: list[dict] = []
    seen_ids: set[str] = set()

    # Source 1: All reviewing/ folder records
    folder_count = 0
    for d in sorted(REVIEWING_DIR.iterdir()):
        if not d.is_dir():
            continue
        ctx = d / "context.txt"
        resp = d / "expected_response.md"
        expl = d / "analysis_explanation.md"
        if not (ctx.exists() and resp.exists() and expl.exists()):
            print(f"[{_ts()}] SKIP {d.name}: missing expected_response.md or analysis_explanation.md")
            continue
        row_id = d.name
        if row_id in seen_ids:
            continue
        seen_ids.add(row_id)
        rows.append({
            "id": row_id,
            "context_path": str(ctx),
            "expected_response_path": str(resp),
            "analysis_explanation_path": str(expl),
        })
        folder_count += 1
    print(f"[{_ts()}] Folder records: {folder_count}")

    # Source 2: Accepted AI teaching cycle rows -> convert to new-schema inline rows
    cycle_count = 0
    for accepted_file in sorted(AI_CYCLES_DIR.glob("accepted_*.jsonl")):
        for line in accepted_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            artifact = str(r.get("artifact", "")).strip()
            expected_response = str(r.get("expected_response", "")).strip()
            review = str(r.get("review", "")).strip()
            task_id = str(r.get("task_id", f"ai-cycle-{cycle_count}"))
            if not artifact or not expected_response or len(expected_response) < 200:
                continue
            if task_id in seen_ids:
                continue
            seen_ids.add(task_id)
            rows.append({
                "id": task_id,
                "artifacts_context": artifact,
                "expected_response": expected_response,
                "analysis_explanation": review or "AI-generated review passed quality gates.",
            })
            cycle_count += 1
    print(f"[{_ts()}] AI cycle accepted rows: {cycle_count}")

    # Source 3: Inline rows from existing JSONLs (non-path-based)
    inline_count = 0
    for src in [TRAINING_DIR / "bola_training.jsonl"]:
        if not src.exists():
            continue
        for i, line in enumerate(src.read_text(encoding="utf-8").splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            # Only take inline rows (not path-based manifest rows)
            if "instruction" in r and "context" in r and "target" in r:
                row_id = f"inline-{src.stem}-{i}"
                if row_id in seen_ids:
                    continue
                seen_ids.add(row_id)
                rows.append({
                    "id": row_id,
                    "instruction": str(r["instruction"]).strip(),
                    "context": str(r["context"]).strip(),
                    "target": str(r["target"]).strip(),
                })
                inline_count += 1
    print(f"[{_ts()}] Inline JSONL rows: {inline_count}")

    # Write combined output
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[{_ts()}] Combined output: {OUTPUT_PATH}")
    print(f"[{_ts()}] Total rows: {len(rows)} (folder={folder_count}, ai_cycles={cycle_count}, inline={inline_count})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
