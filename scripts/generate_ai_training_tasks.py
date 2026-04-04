#!/usr/bin/env python3
"""Generate AI prompt tasks for synthetic security training data production.

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
        required_patterns="BOLA cross-tenant read, BAC role pivot, lifecycle integrity drift, nested linked-resource access, verbose error leakage",
    ),
    TrainingTask(
        sector="healthcare claims processing",
        architecture="GraphQL gateway + microservices + document store",
        artifact_type="network log",
        complexity="high",
        required_patterns="resolver ownership miss, graph traversal injection, metadata side-channel leakage, mutation write escalation, fail-open on timeout",
    ),
    TrainingTask(
        sector="public utility billing",
        architecture="REST + legacy SOAP bridge + shared admin console",
        artifact_type="schema",
        complexity="medium",
        required_patterns="tenant scoping gap, parent-child dependency bypass, insecure workflow decoupling, integrity downgrade via versioning",
    ),
    TrainingTask(
        sector="defense contractor supply chain",
        architecture="REST + event bus + multi-tenant SaaS",
        artifact_type="API documentation",
        complexity="high",
        required_patterns="cross-service identity propagation drift, confused deputy via export service, race condition on approval workflow, schema over-exposure",
    ),
    TrainingTask(
        sector="financial services lending",
        architecture="REST + OAuth2 + webhook callbacks",
        artifact_type="network log",
        complexity="high",
        required_patterns="token scope leakage, implicit callback trust, mass assignment via loan fields, anti-forensic audit log modification",
    ),
]

PHASE1_SMALL_MODEL_TASKS: list[TrainingTask] = [
    TrainingTask(
        sector="state government licensing",
        architecture="REST + PostgreSQL + tenant-scoped case workflow",
        artifact_type="API documentation",
        complexity="medium",
        required_patterns="cross-tenant read, linked-resource ownership bypass, functional role pivot",
    ),
    TrainingTask(
        sector="regional healthcare provider",
        architecture="GraphQL gateway + patient notes service",
        artifact_type="network log",
        complexity="medium",
        required_patterns="resolver ownership miss, record-id comment disclosure, resolver traversal abuse, mutation write escalation",
    ),
    TrainingTask(
        sector="public utility operations",
        architecture="REST + job queue + internal admin panel",
        artifact_type="schema",
        complexity="medium",
        required_patterns="parent-child relationship bypass, queue payload object leak, unauthorized status update, verbose error leakage",
    ),
]


def _output_path(base_dir: Path) -> Path:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = base_dir / "data" / "training" / "ai_tasks"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"teacher_tasks_{ts}.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate AI training task pack for security model teaching")
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
