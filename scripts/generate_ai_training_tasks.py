#!/usr/bin/env python3
"""Generate AI prompt tasks for synthetic security training data production.

This script does not call external models. It creates a task pack (JSONL) that
can be executed by local AI agents to produce:
1) realistic docs/schemas/network logs
2) gold expected responses
3) reviewer feedback loops

Refactored to support Wide-Spectrum vulnerability ontology (ICS/SCADA, Cloud IAM,
Telecom, BFLA, BOLA, SSTI, etc.).

New: --from-reviewing mode scans the hierarchical reviewing folder structure and
builds a task pack from existing context.txt / expected_response.md files, enabling
the teaching cycle to re-validate or regenerate gold responses for every example.
"""

from __future__ import annotations

import argparse
import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from jinja2 import Template

from training.ai_teacher_prompts import (
    EXPECTED_RESPONSE_PROMPT,
    REVIEW_PROMPT,
    TEACHER_SYSTEM_PROMPT,
    TrainingTask,
    build_scenario_prompt,
)


DEFAULT_TASKS: list[TrainingTask] = [
    TrainingTask(
        sector="Smart City Infrastructure",
        architecture="REST + Node.js + SCADA Bridge",
        artifact_types="network log",
        complexity="high",
        required_patterns="HTTP Verb/Method Tampering (1.6), Insecure Deserialization leading to RCE (10.3)",
    ),
    TrainingTask(
        sector="Telecommunications 5G Core",
        architecture="Kong Gateway + Node.js + UDM Database",
        artifact_types="network log",
        complexity="high",
        required_patterns="JWT Algorithm Confusion (10.2), Excessive Data Exposure of cryptographic keys (3.1)",
    ),
    TrainingTask(
        sector="Cloud IAM & B2B SaaS",
        architecture="AWS API Gateway + Node.js Nunjucks Worker",
        artifact_types="API documentation",
        complexity="high",
        required_patterns="Broken Function Level Authorization / BFLA (1.2), Server-Side Template Injection / SSTI (7.3)",
    ),
    TrainingTask(
        sector="Aviation & Global PSS",
        architecture="Akamai Edge + Java Spring Boot XML Parser",
        artifact_types="API documentation",
        complexity="high",
        required_patterns="XML External Entity / XXE (7.1), Internal unauthenticated SSRF (6.1), Internal BOLA (1.3)",
    ),
    TrainingTask(
        sector="Defense Industrial Base",
        architecture="REST + Event Bus + CI/CD Pipelines",
        artifact_types="schema",
        complexity="high",
        required_patterns="Infrastructure-as-Code (IaC) state file exposure (4.4), Unverified firmware payload delivery (4.5)",
    ),
]

PHASE1_SMALL_MODEL_TASKS: list[TrainingTask] = [
    TrainingTask(
        sector="Healthcare Claims Processing",
        architecture="GraphQL Gateway + Microservices",
        artifact_types="API documentation",
        complexity="medium",
        required_patterns="Resolver graph traversal injection (5.2), Alias batching BOLA (1.9)",
    ),
    TrainingTask(
        sector="EdTech Remote Assessment",
        architecture="REST + Prisma ORM + PostgreSQL",
        artifact_types="network log",
        complexity="medium",
        required_patterns="Mass Assignment auto-binding (1.12), Trusting client-side state / Grading bypass (3.1)",
    ),
    TrainingTask(
        sector="Financial Services Payments",
        architecture="REST + OAuth2 + Webhook Callbacks",
        artifact_types="schema",
        complexity="medium",
        required_patterns="Implicit trust in callbacks without signature validation (3.4), Race condition during ledger sync (8.1)",
    ),
]


OPENAPI_TEMPLATE = Template(
    """openapi: 3.0.3
info:
  title: {{ service_name }} API
  version: "1.0.0"
paths:
  {{ standard_path }}:
    {{ standard_method }}:
      operationId: {{ standard_operation }}
      security:
        - bearerAuth: []
      parameters:
        - in: header
          name: X-Request-ID
          schema: { type: string }
      responses:
        "200":
          description: standard operational result
  {{ sensitive_path }}:
    {{ sensitive_method }}:
      operationId: {{ sensitive_operation }}
      security:
        - bearerAuth: []
      parameters:
        - in: header
          name: X-Request-ID
          schema: { type: string }
      requestBody:
        content:
          application/json:
            schema:
              type: object
      responses:
        "200":
          description: potentially vulnerable high-privilege result
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
"""
)

HAR_TEMPLATE = Template(
    """{
  "log": {
    "version": "1.2",
    "creator": { "name": "wide-spectrum-generator", "version": "2.0" },
    "entries": [
      {
        "startedDateTime": "{{ timestamp }}",
        "request": {
          "method": "{{ standard_method }}",
          "url": "https://api.internal.network{{ standard_path }}",
          "httpVersion": "HTTP/2.0",
          "headers": [
            { "name": "Authorization", "value": "Bearer {{ token_standard }}" },
            { "name": "Content-Type", "value": "application/json" }
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{\\"context\\": \\"baseline_safe_request\\"}"
          }
        },
        "response": { "status": 200, "statusText": "OK" },
        "time": 118
      },
      {
        "startedDateTime": "{{ timestamp }}",
        "request": {
          "method": "{{ anomalous_method }}",
          "url": "https://api.internal.network{{ sensitive_path }}",
          "httpVersion": "HTTP/2.0",
          "headers": [
            { "name": "Authorization", "value": "Bearer {{ token_anomalous }}" },
            { "name": "Content-Type", "value": "application/json" }
          ],
          "postData": {
            "mimeType": "application/json",
            "text": "{{ payload_anomalous }}"
          }
        },
        "response": { "status": 200, "statusText": "OK" },
        "time": 405
      }
    ]
  }
}"""
)

SQL_DDL_TEMPLATE = Template(
    """CREATE TABLE system_tenant (
  tenant_id VARCHAR(64) PRIMARY KEY,
  tenant_name VARCHAR(128) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE {{ object_table }} (
  {{ object_id }} UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id VARCHAR(64) REFERENCES system_tenant(tenant_id),
  owner_id VARCHAR(64) NOT NULL,
  
  -- Core Data
  configuration_payload JSONB DEFAULT '{}',
  
  -- Administrative/Vulnerable targets (e.g. Mass Assignment)
  is_admin_override BOOLEAN DEFAULT FALSE,
  security_clearance_level INT DEFAULT 1,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_{{ object_table }}_tenant ON {{ object_table }}(tenant_id);

-- Secure query requires tenant_id and owner_id validation.
-- Vulnerable configurations bypass these checks or allow direct payload injection.
"""
)


def _artifact_template_for(task: TrainingTask, idx: int) -> str:
    sector_slug = task.sector.split()[0].lower()
    service_name = f"{sector_slug}-core-service-{idx}"
    
    # Generate domain-specific paths to give the LLM better grounding
    standard_path = f"/api/v1/{sector_slug}/assets/{idx}/telemetry"
    sensitive_path = f"/api/v1/{sector_slug}/assets/{idx}/configure"
    
    # Introduce method variations for advanced tests (like Verb Tampering)
    standard_method = "GET"
    anomalous_method = "PATCH"

    if "network log" in task.artifact_types.lower():
        return HAR_TEMPLATE.render(
            timestamp=datetime.now(timezone.utc).isoformat(),
            standard_path=standard_path,
            sensitive_path=sensitive_path,
            standard_method=standard_method,
            anomalous_method=anomalous_method,
            token_standard=f"eyJhbGciOiJSUzI1Ni...[Standard_User_{uuid.uuid4().hex[:6]}]",
            token_anomalous=f"eyJhbGciOiJIUzI1Ni...[Anomalous_or_Forged_Token_{uuid.uuid4().hex[:6]}]",
            payload_anomalous="{\\\"injected_role\\\": \\\"admin\\\", \\\"target_node\\\": \\\"internal_backend\\\"}"
        )

    if "schema" in task.artifact_types.lower():
        return SQL_DDL_TEMPLATE.render(
            object_table=f"{sector_slug}_infrastructure_node",
            object_id=f"node_id",
        )

    # Default to OpenAPI-like structural blueprint
    return OPENAPI_TEMPLATE.render(
        service_name=service_name,
        standard_path=standard_path,
        sensitive_path=sensitive_path,
        standard_method="GET",
        sensitive_method="POST",
        standard_operation=f"get{sector_slug.capitalize()}Telemetry",
        sensitive_operation=f"update{sector_slug.capitalize()}Configuration",
    )


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
        help="Task profile to generate (ignored when --from-reviewing is set)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=25,
        help="Maximum records buffered before flush (memory-safe streaming write).",
    )
    parser.add_argument(
        "--from-reviewing",
        action="store_true",
        help="Build task pack from existing reviewing folder examples instead of template tasks",
    )
    args = parser.parse_args()
    repo_root = Path(args.repo_root).resolve()
    out_file = _output_path(repo_root)

    if args.from_reviewing:
        from training.reviewing_iter import iter_leaf_folders
        reviewing_root = repo_root / "data" / "training" / "reviewing"
        batch: list[str] = []
        total = 0
        with out_file.open("w", encoding="utf-8") as f:
            for leaf in iter_leaf_folders(reviewing_root):
                ctx_file = leaf / "context.txt"
                resp_file = leaf / "expected_response.md"
                if not ctx_file.exists() or not resp_file.exists():
                    continue
                total += 1
                record = {
                    "task_id": f"REVIEW-{leaf.name}",
                    "system_prompt": TEACHER_SYSTEM_PROMPT,
                    "scenario_prompt": ctx_file.read_text(encoding="utf-8"),
                    "expected_response_prompt": EXPECTED_RESPONSE_PROMPT,
                    "review_prompt": REVIEW_PROMPT,
                    "artifact_template": ctx_file.read_text(encoding="utf-8"),
                    "metadata": {
                        "source_folder": str(leaf.relative_to(repo_root)),
                        "phase": "reviewing",
                        "blueprint": "from-reviewing",
                    },
                }
                expl_file = leaf / "analysis_explanation.md"
                if expl_file.exists():
                    record["analysis_explanation"] = expl_file.read_text(encoding="utf-8")
                record["gold_expected_response"] = resp_file.read_text(encoding="utf-8")
                batch.append(json.dumps(record, ensure_ascii=False))
                if len(batch) >= args.batch_size:
                    f.write("\n".join(batch) + "\n")
                    batch.clear()
            if batch:
                f.write("\n".join(batch) + "\n")
        print(f"Wrote task pack (from-reviewing): {out_file}")
        print(f"Examples found: {total}")
        return 0

    if args.phase == "small-model-phase1":
        tasks = PHASE1_SMALL_MODEL_TASKS
    else:
        tasks = DEFAULT_TASKS
    expected_prompt = EXPECTED_RESPONSE_PROMPT
    phase_instructions = ""

    batch_list: list[str] = []
    with out_file.open("w", encoding="utf-8") as f:
        for idx, task in enumerate(tasks, start=1):
            record = {
                "task_id": f"TASK-{idx:03d}",
                "system_prompt": TEACHER_SYSTEM_PROMPT,
                "scenario_prompt": build_scenario_prompt(task),
                "expected_response_prompt": expected_prompt,
                "review_prompt": REVIEW_PROMPT,
                "artifact_template": _artifact_template_for(task, idx),
                "metadata": {
                    "sector": task.sector,
                    "architecture": task.architecture,
                    "artifact_types": task.artifact_types,
                    "complexity": task.complexity,
                    "phase": args.phase,
                    "blueprint": "generic",
                },
            }
            if phase_instructions:
                record["phase_instructions"] = phase_instructions
            batch_list.append(json.dumps(record, ensure_ascii=False))
            if len(batch_list) >= args.batch_size:
                f.write("\n".join(batch_list) + "\n")
                batch_list.clear()
        if batch_list:
            f.write("\n".join(batch_list) + "\n")

    print(f"Wrote task pack: {out_file}")
    print(f"Tasks: {len(tasks)}")
    print(f"Phase: {args.phase}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())