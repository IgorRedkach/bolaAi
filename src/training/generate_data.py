#!/usr/bin/env python3
"""Prompt-first learning-set runbook helpers.

This module intentionally avoids hardcoded synthetic data generation logic.
It only provides prompt bundles and checkpoint templates for manual prompt
execution when authoring learning sets.
"""

from __future__ import annotations

from dataclasses import dataclass

from training.ai_teacher_prompts import (
    AUTHENTICITY_REVIEW_PROMPT,
    CHECKPOINT_TRACKING_PROMPT,
    DOC_STRATEGY_PROMPT,
    DOCUMENT_BLUEPRINT_PROMPT,
    DOCUMENT_CONTENT_PROMPT,
    DOCUMENT_SCALE_AND_VARIABILITY_PROMPT,
    EXPECTED_RESPONSE_PROMPT,
    EXPLANATION_PROMPT,
    INDUSTRY_ARCHITECTURE_PROMPT,
    LEARNING_PATH_INTENT,
    LOG_DECISION_PROMPT,
    PATTERN_SELECTION_PROMPT,
    REVIEW_PROMPT,
    TAXONOMY_PATH,
    TEACHER_SYSTEM_PROMPT,
    VULNERABILITY_EMBEDDING_PROMPT,
)


@dataclass(frozen=True)
class LearningSetPromptInputs:
    set_id: str
    architecture_summary: str = ""
    selected_patterns: str = ""
    blueprint_item: str = ""
    context_excerpt: str = ""
    doc_strategy_summary: str = ""


CHECKPOINTS: tuple[str, ...] = (
    "Industry selected and justified",
    "Architecture created and detailed",
    "Documentation strategy planned",
    "Documentation bundle generated",
    "Vulnerability classes selected from taxonomy",
    "Vulnerabilities embedded into architecture artifacts",
    "Optional log/HAR decision recorded",
    "Context evidence assembled",
    "Expected response generated with reproduction steps",
    "Separate explanation generated",
    "Grounding review completed",
    "Authenticity review completed",
    "Documentation bytes excluding logs/HAR >= 10MB before optional logs/HAR",
    "No repetitive copy/paste or synthetic padding patterns",
)


def build_learning_set_prompt_pack(inputs: LearningSetPromptInputs) -> dict[str, str]:
    """Build the stage prompt pack for a single learning set."""
    learning_intent = LEARNING_PATH_INTENT.format(taxonomy_path=TAXONOMY_PATH)
    return {
        "system": TEACHER_SYSTEM_PROMPT,
        "stage_1_industry_architecture": INDUSTRY_ARCHITECTURE_PROMPT.format(
            learning_path_intent=learning_intent,
        ),
        "stage_2_doc_strategy": DOC_STRATEGY_PROMPT,
        "stage_3_pattern_selection": PATTERN_SELECTION_PROMPT.format(
            taxonomy_path=TAXONOMY_PATH,
            architecture_summary=inputs.architecture_summary or "<architecture summary pending>",
        ),
        "stage_4_scale_variability_plan": DOCUMENT_SCALE_AND_VARIABILITY_PROMPT,
        "stage_5_document_blueprint": DOCUMENT_BLUEPRINT_PROMPT
        + "\n\nArchitecture summary:\n"
        + (inputs.architecture_summary or "<architecture summary pending>")
        + "\n\nDocumentation strategy summary:\n"
        + (inputs.doc_strategy_summary or "<doc strategy pending>")
        + "\n\nSelected patterns:\n"
        + (inputs.selected_patterns or "<patterns pending>"),
        "stage_6_document_content": DOCUMENT_CONTENT_PROMPT
        + "\n\nArchitecture summary:\n"
        + (inputs.architecture_summary or "<architecture summary pending>")
        + "\n\nSelected patterns:\n"
        + (inputs.selected_patterns or "<patterns pending>")
        + "\n\nBlueprint item:\n"
        + (inputs.blueprint_item or "<document blueprint pending>"),
        "stage_7_vulnerability_embedding": VULNERABILITY_EMBEDDING_PROMPT.format(
            taxonomy_path=TAXONOMY_PATH,
        ),
        "stage_8_log_decision": LOG_DECISION_PROMPT,
        "stage_9_expected_response": EXPECTED_RESPONSE_PROMPT
        + "\n\nContext excerpt:\n"
        + (inputs.context_excerpt or "<context pending>"),
        "stage_10_explanation": EXPLANATION_PROMPT
        + "\n\nContext excerpt:\n"
        + (inputs.context_excerpt or "<context pending>"),
        "stage_11_grounding_review": REVIEW_PROMPT
        + "\n\nContext excerpt:\n"
        + (inputs.context_excerpt or "<context pending>"),
        "stage_12_authenticity_review": AUTHENTICITY_REVIEW_PROMPT,
        "stage_13_checkpoint_report": CHECKPOINT_TRACKING_PROMPT,
    }


def render_checkpoint_template(record_path: str) -> str:
    """Return markdown checklist template for one prompt run."""
    lines = [f"# Prompt Run Checks for `{record_path}`", ""]
    for item in CHECKPOINTS:
        lines.append(f"- [ ] {item}")
    lines.extend(
        [
            "",
            "## Evidence",
            "- context_path:",
            "- expected_response_path:",
            "- analysis_explanation_path:",
            "- notes:",
            "",
            "## Validation",
            "- taxonomy_coverage:",
            "- grounding_review:",
            "- unresolved_risks:",
        ]
    )
    return "\n".join(lines) + "\n"
