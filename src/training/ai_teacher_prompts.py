"""Prompt templates for AI-assisted BOLA training data generation.

These prompts are designed for generating high-quality synthetic artifacts
and expected answers that are grounded, auditor-friendly, and security-focused.
"""

from __future__ import annotations

from dataclasses import dataclass


TEACHER_SYSTEM_PROMPT = """You are a senior application security engineer.
Your task is to generate realistic security-review artifacts for BOLA analysis.

Hard requirements:
- Focus on object-level authorization (BOLA) and related authz logic only.
- Keep artifacts realistic for regulated US sectors (government, healthcare, finance, utilities).
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
- Required BOLA patterns: {required_patterns}

Output format (strict markdown):
1. Project context (4-8 bullets)
2. Authorization model (roles, tenants, ownership rules)
3. API/spec/log content:
   - If artifact_type is API doc: concrete endpoints and request/response examples.
   - If artifact_type is schema: tables/objects/relationships and key fields.
   - If artifact_type is network log: realistic request traces with IDs/tokens placeholders.
4. Insert exactly {risk_count} intentional high-risk BOLA opportunities.
5. Include a short "Ground truth risk list" section mapping each risk to endpoint/object.

Constraints:
- Every path/object in risk list must appear verbatim in the artifact content.
- Include at least one read-path and one write-path BOLA risk.
- Avoid generic filler text; keep it actionable for auditors.
"""


EXPECTED_RESPONSE_PROMPT = """You are producing a gold-standard expected analysis response
for a BOLA detection assistant. Use ONLY the provided artifact.

Return strict markdown sections:
## Findings
- 3-8 findings max, each containing:
  - exact endpoint/object (verbatim from artifact)
  - BOLA rationale (ownership/object-level access gap)
  - two-valid-user-token verification procedure

## Verification Runbook
- Step-by-step sequence with Token A / Token B on same object ID.
- Include expected outcomes for secure vs vulnerable behavior.

## False-positive Guardrails
- List what should NOT be considered BOLA in this artifact.

## Grounding Self-check
- Bullet list of all endpoints/objects referenced in your answer.

Quality constraints:
- No invented endpoint/path/object names.
- No "test without token" logic for BOLA confirmation.
- No implementation patch code; auditor procedure only.
"""


REVIEW_PROMPT = """Review the generated artifact and expected response.
Score each category from 0-5 and explain briefly:
1) Grounding accuracy
2) BOLA specificity
3) Verification validity (two valid users)
4) Auditor actionability
5) Format consistency

Then return:
- PASS/FAIL (PASS only if every score >= 4)
- A corrected expected response if FAIL
- A list of fix actions to improve future data generation prompts
"""

PHASE1_SMALL_MODEL_INSTRUCTIONS = """Phase 1 objective: improve a smaller local model (3B/3.5B-class)
for reliable BOLA analysis without relying on larger-model capacity.

Extra constraints for generated gold responses:
- Each finding must include one exact endpoint/object and one concrete verification step.
- Prefer explicit, short runbooks over broad narrative.
- Add a final "Uncertainty" bullet when ownership controls are undocumented.
"""

PHASE1_EXPECTED_RESPONSE_PROMPT = """You are producing a gold-standard expected analysis response
for a smaller BOLA detection assistant model. Use ONLY the provided artifacts.

Return strict markdown sections:
## Findings
- each containing:
  - exact endpoint/object (verbatim from artifact)
  - BOLA rationale (ownership/object-level access gap)

## Verification Runbook
- 3-6 concise steps.
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
    risk_count: int


def build_scenario_prompt(task: TrainingTask) -> str:
    return SCENARIO_AUTHOR_PROMPT.format(
        sector=task.sector,
        architecture=task.architecture,
        artifact_type=task.artifact_type,
        complexity=task.complexity,
        required_patterns=task.required_patterns,
        risk_count=task.risk_count,
    )

