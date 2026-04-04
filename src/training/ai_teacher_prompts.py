"""Prompt templates for AI-assisted security training data generation.

These prompts are designed for generating high-quality synthetic artifacts
and expected answers that are grounded, auditor-friendly, and security-focused.
"""

from __future__ import annotations

from dataclasses import dataclass


TEACHER_SYSTEM_PROMPT = """You are a senior application security engineer.
Your task is to generate realistic security-review artifacts for documentation/log investigation.

Hard requirements:
- Investigate the full vulnerability taxonomy: BOLA (primary), broken access control,
  insecure design, integrity failures, injection, misconfiguration, logging/alerting failures,
  exceptional-condition handling, authentication boundaries, and cryptographic weaknesses.
- Treat the taxonomy as non-exhaustive: include additional closely related classes when evidenced.
- Keep artifacts realistic for regulated sectors (government, healthcare, finance, utilities, defense, critical infrastructure).
- Do not include internet calls or third-party SaaS assumptions unless explicitly requested.
- Do not invent technologies not listed in the task input.
- Include sufficient detail for deterministic verification.
"""


SCENARIO_AUTHOR_PROMPT = """Generate a synthetic but realistic project artifact bundle.

Inputs:
- Sector: {sector}
- Architecture: {architecture}
- Artifact type: {artifact_type}
- Complexity level: {complexity}
- Required vulnerability patterns: {required_patterns}

Output format (strict markdown):
1. Project context (concise, evidence-friendly)
2. Authorization model (roles, tenants, ownership rules)
3. API/spec/log content:
   - If artifact_type is API doc: concrete endpoints and request/response examples.
   - If artifact_type is schema: tables/objects/relationships and key fields.
   - If artifact_type is network log: realistic request traces with IDs/tokens placeholders.
4. Insert a diverse set of intentional high-risk opportunities across relevant vulnerability classes. Favor quality and realism over a fixed count.
5. Include a short "Ground truth risk list" section mapping each risk to endpoint/object/vulnerability class.

Constraints:
- Every path/object in risk list must appear verbatim in the artifact content.
- Include both read-path and write-path security risks when relevant.
- Avoid generic filler text; keep it actionable for auditors.
"""


EXPECTED_RESPONSE_PROMPT = """You are producing a gold-standard expected analysis response
for a security investigation assistant. Use ONLY the provided artifact.

Return strict markdown sections:
## Findings
- each containing:
  - vulnerability class (taxonomy-aligned; non-exhaustive when evidence supports adjacent classes)
  - exact endpoint/object (verbatim from artifact)
  - rationale grounded in artifact evidence
  - concrete verification procedure

## Verification Runbook
- Step-by-step sequence grounded to the artifact.
- Use two valid-user comparative checks for object-boundary claims.
- Include expected outcomes for secure vs vulnerable behavior.

## False-positive Guardrails
- List what should NOT be considered BOLA in this artifact.

## Grounding Self-check
- Bullet list of all endpoints/objects referenced in your answer.

## Uncertainty
- State unknowns when ownership/enforcement controls are undocumented.

Quality constraints:
- No invented endpoint/path/object names.
- No "test without token" logic for object-boundary confirmation.
- No implementation patch code; auditor procedure only.
"""


REVIEW_PROMPT = """Review the generated artifact and expected response.
Score each category from 0-5 and explain briefly:
1) Grounding accuracy
2) Vulnerability-class correctness (BOLA-priority + adjacent class correctness)
3) Verification validity (comparative checks where required)
4) Auditor actionability
5) Format consistency

Then return:
- PASS/FAIL (PASS only when there are no critical grounding/logic failures and overall quality is deployment-usable)
- A corrected expected response if FAIL
- A list of fix actions to improve future data generation prompts
"""

PHASE1_SMALL_MODEL_INSTRUCTIONS = """Phase 1 objective: improve a smaller local model (3B/3.5B-class)
for reliable vulnerability investigation without relying on larger-model capacity.

Extra constraints for generated gold responses:
- Each finding must include one exact endpoint/object and one concrete verification step.
- Prefer explicit, short runbooks over broad narrative.
- Add a final "Uncertainty" bullet when ownership controls are undocumented.
"""

PHASE1_EXPECTED_RESPONSE_PROMPT = """You are producing a gold-standard expected analysis response
for a smaller security investigation assistant model. Use ONLY the provided artifacts.

Return strict markdown sections:
## Findings
- each containing:
  - vulnerability class (prefer BOLA when evidence supports object-boundary failure)
  - exact endpoint/object (verbatim from artifact)
  - rationale grounded in artifact evidence

## Verification Runbook
- Concise steps sufficient for deterministic auditor execution.
- Include expected outcomes for secure vs vulnerable behavior.

## Grounding Self-check
- Bullet list of endpoints/objects used in this answer.

## Uncertainty
- One bullet that states what cannot be concluded from the artifact.

Quality constraints:
- No invented endpoint/path/object names.
- No "test without token" logic for BOLA confirmation.
- No patch code; auditor procedure only.
"""


@dataclass(frozen=True)
class TrainingTask:
    sector: str
    architecture: str
    artifact_type: str
    complexity: str
    required_patterns: str


def build_scenario_prompt(task: TrainingTask) -> str:
    return SCENARIO_AUTHOR_PROMPT.format(
        sector=task.sector,
        architecture=task.architecture,
        artifact_type=task.artifact_type,
        complexity=task.complexity,
        required_patterns=task.required_patterns,
    )

