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
    PHASE1_EXPECTED_RESPONSE_PROMPT,
    PHASE1_SMALL_MODEL_INSTRUCTIONS,
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

PHASE1_SMALL_MODEL_TASKS: list[TrainingTask] = [
    TrainingTask(
        sector="state government licensing",
        architecture="REST + PostgreSQL + tenant-scoped case workflow",
        artifact_type="API documentation",
        complexity="medium",
        required_patterns="cross-tenant read, write-by-foreign-id, linked-resource ownership bypass",
        risk_count=3,
    ),
    TrainingTask(
        sector="regional healthcare provider",
        architecture="GraphQL gateway + patient notes service",
        artifact_type="network log",
        complexity="medium",
        required_patterns="resolver ownership miss, record-id comment disclosure, mutation write escalation",
        risk_count=3,
    ),
    TrainingTask(
        sector="public utility operations",
        architecture="REST + job queue + internal admin panel",
        artifact_type="schema",
        complexity="medium",
        required_patterns="parent-child relationship bypass, queue payload object leak, unauthorized status update",
        risk_count=3,
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
    parser.add_argument(
        "--phase",
        choices=["default", "small-model-phase1"],
        default="small-model-phase1",
        help="Task profile to generate",
    )
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_file = _output_path(repo_root)

    if args.phase == "small-model-phase1":
        tasks = PHASE1_SMALL_MODEL_TASKS
        expected_prompt = PHASE1_EXPECTED_RESPONSE_PROMPT
        phase_instructions = PHASE1_SMALL_MODEL_INSTRUCTIONS
    else:
        tasks = DEFAULT_TASKS
        expected_prompt = EXPECTED_RESPONSE_PROMPT
        phase_instructions = ""

    with out_file.open("w", encoding="utf-8") as f:
        for idx, task in enumerate(tasks, start=1):
            record = {
                "task_id": f"TASK-{idx:03d}",
                "system_prompt": TEACHER_SYSTEM_PROMPT,
                "scenario_prompt": build_scenario_prompt(task),
                "expected_response_prompt": expected_prompt,
                "review_prompt": REVIEW_PROMPT,
                "metadata": {
                    "sector": task.sector,
                    "architecture": task.architecture,
                    "artifact_type": task.artifact_type,
                    "complexity": task.complexity,
                    "phase": args.phase,
                },
            }
            if phase_instructions:
                record["phase_instructions"] = phase_instructions
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Wrote task pack: {out_file}")
    print(f"Tasks: {len(tasks)}")
    print(f"Phase: {args.phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

