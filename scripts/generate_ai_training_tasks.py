#!/usr/bin/env python3
"""Generate AI prompt tasks for synthetic BOLA training data production.

This script does not call external models. It creates a task pack (JSONL) that
can be executed by local AI agents to produce:
1) realistic docs/schemas/network logs
2) gold expected responses
3) reviewer feedback loops
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from training.ai_teacher_prompts import (
    EXPECTED_RESPONSE_PROMPT,
    REVIEW_PROMPT,
    TEACHER_SYSTEM_PROMPT,
    TrainingTask,
    build_scenario_prompt,
)


DEFAULT_TASKS: list[TrainingTask] = [
    TrainingTask(
        sector="US municipal government",
        architecture="REST + PostgreSQL + role-based reviewer portal",
        artifact_type="API documentation",
        complexity="high",
        required_patterns="cross-tenant read, write-by-foreign-id, nested linked-resource access",
        risk_count=5,
    ),
    TrainingTask(
        sector="healthcare claims processing",
        architecture="GraphQL gateway + microservices + document store",
        artifact_type="network log",
        complexity="high",
        required_patterns="resolver-level ownership miss, list enumeration, mutation write escalation",
        risk_count=5,
    ),
    TrainingTask(
        sector="public utility billing",
        architecture="REST + legacy SOAP bridge + shared admin console",
        artifact_type="schema",
        complexity="medium",
        required_patterns="tenant scoping gap, parent-child relationship bypass, invoice write abuse",
        risk_count=4,
    ),
]


def _output_path(base_dir: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = base_dir / "data" / "training" / "ai_tasks"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"teacher_tasks_{ts}.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AI training task pack for BOLA model teaching")
    parser.add_argument(
        "--repo-root",
        default=str(Path(__file__).resolve().parents[1]),
        help="Repository root path",
    )
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_file = _output_path(repo_root)

    with out_file.open("w", encoding="utf-8") as f:
        for idx, task in enumerate(DEFAULT_TASKS, start=1):
            record = {
                "task_id": f"TASK-{idx:03d}",
                "system_prompt": TEACHER_SYSTEM_PROMPT,
                "scenario_prompt": build_scenario_prompt(task),
                "expected_response_prompt": EXPECTED_RESPONSE_PROMPT,
                "review_prompt": REVIEW_PROMPT,
                "metadata": {
                    "sector": task.sector,
                    "architecture": task.architecture,
                    "artifact_type": task.artifact_type,
                    "complexity": task.complexity,
                },
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Wrote task pack: {out_file}")
    print(f"Tasks: {len(DEFAULT_TASKS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

