"""Prompts for ExampleGenerator — isolated so they can evolve independently.

This module is intentionally decoupled from the main analysis prompts so that:
1. It can be trained/fine-tuned separately (separate JSONL data, separate model).
2. It can be swapped out for a domain-specific examples model without touching
   the core BOLA analysis pipeline.
3. Prompt iteration for example quality does not risk regressing security analysis.

API type detection signals are also centralized here.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# API type detection
# ---------------------------------------------------------------------------

GRAPHQL_SIGNALS = (
    "/graphql", "query {", "mutation {", "__typename", "gql`",
    "graphql endpoint", "introspection", "apollo", "hasura",
)

SOQL_SIGNALS = (
    "aura", "lightning.force.com", "salesforce", "soql", "apex",
    "getrecordwithfields", "updaterecord", "soql select",
)

REST_FALLBACK = True  # always produces REST examples when no other type detected


def detect_api_type(context: str) -> str:
    """Detect the primary API type from HAR or document context.

    Returns one of: 'graphql', 'soql', 'rest', 'mixed'.
    """
    lower = context.lower() if context else ""
    has_graphql = any(sig in lower for sig in GRAPHQL_SIGNALS)
    has_soql = any(sig in lower for sig in SOQL_SIGNALS)

    if has_graphql and has_soql:
        return "mixed"
    if has_graphql:
        return "graphql"
    if has_soql:
        return "soql"
    return "rest"


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

EXAMPLES_SYSTEM_PROMPT = """\
You are a security verification example generator. Your sole job is to produce
copy-pasteable API requests that an auditor can use to verify a specific
authorization vulnerability finding.

STRICT RULES:
1. Use ONLY endpoints, field names, and paths that appear in the provided evidence.
2. Never invent endpoints, field names, query types, or parameter names.
3. For BOLA/authorization findings, always produce a TWO-TOKEN comparison:
   - Token A: the legitimate owner's token.
   - Token B: a different user's token.
4. Output ONLY the requested example format — no prose explanation, no preamble.
5. For GraphQL: produce valid GraphQL syntax using field names from the evidence.
6. For REST: produce valid curl commands.
7. For SOQL: produce SELECT statements.
8. Mark placeholder values with <angle_brackets>.
9. If there is not enough evidence to produce a typed example, output:
   NO_EXAMPLE: <brief reason>
"""


# ---------------------------------------------------------------------------
# User prompt builders
# ---------------------------------------------------------------------------

def build_rest_example_prompt(
    pattern_id: str,
    pattern_name: str,
    evidence: str,
    attack_delta: str,
    endpoint: str,
    method: str = "GET",
) -> str:
    return (
        f"Generate a REST verification example for the following finding.\n\n"
        f"Pattern: {pattern_id} — {pattern_name}\n"
        f"Endpoint: {method} {endpoint}\n"
        f"Attack vector: {attack_delta}\n"
        f"Evidence: {evidence[:300]}\n\n"
        f"Output two curl commands:\n"
        f"1. curl with Token A (legitimate owner)\n"
        f"2. curl with Token B (different user, same object ID)\n"
        f"Use '<id-owned-by-A>' for the object ID placeholder."
    )


def build_graphql_example_prompt(
    pattern_id: str,
    pattern_name: str,
    evidence: str,
    attack_delta: str,
    endpoint: str,
) -> str:
    return (
        f"Generate a GraphQL verification example for the following finding.\n\n"
        f"Pattern: {pattern_id} — {pattern_name}\n"
        f"GraphQL endpoint: {endpoint}\n"
        f"Attack vector: {attack_delta}\n"
        f"Evidence (use ONLY field names from this): {evidence[:400]}\n\n"
        f"Output:\n"
        f"1. A GraphQL query or mutation that reproduces the attack vector.\n"
        f"2. The HTTP request wrapper (curl with Authorization header).\n"
        f"Produce two variants: one with Token A (owner), one with Token B (other user).\n"
        f"Use only field names visible in the evidence above."
    )


def build_soql_example_prompt(
    pattern_id: str,
    pattern_name: str,
    evidence: str,
    attack_delta: str,
) -> str:
    return (
        f"Generate a SOQL / Salesforce Apex verification example for the following finding.\n\n"
        f"Pattern: {pattern_id} — {pattern_name}\n"
        f"Attack vector: {attack_delta}\n"
        f"Evidence: {evidence[:400]}\n\n"
        f"Output:\n"
        f"1. A SOQL SELECT statement that reproduces the cross-object access.\n"
        f"2. A Salesforce REST API call (curl) targeting the same record with two tokens.\n"
        f"Use only object/field names visible in the evidence."
    )


def build_mixed_example_prompt(
    pattern_id: str,
    pattern_name: str,
    evidence: str,
    attack_delta: str,
    endpoint: str,
    method: str = "POST",
) -> str:
    return (
        f"Generate verification examples for a mixed REST+GraphQL artifact.\n\n"
        f"Pattern: {pattern_id} — {pattern_name}\n"
        f"Endpoint: {method} {endpoint}\n"
        f"Attack vector: {attack_delta}\n"
        f"Evidence: {evidence[:300]}\n\n"
        f"Output:\n"
        f"1. A REST curl pair (Token A, Token B).\n"
        f"2. A GraphQL query variant if GraphQL is present in the evidence.\n"
        f"Use only names visible in the evidence."
    )


def select_prompt(
    api_type: str,
    *,
    pattern_id: str,
    pattern_name: str,
    evidence: str,
    attack_delta: str,
    endpoint: str,
    method: str = "GET",
) -> str:
    """Pick the right prompt builder based on the detected API type."""
    if api_type == "graphql":
        return build_graphql_example_prompt(
            pattern_id, pattern_name, evidence, attack_delta, endpoint
        )
    if api_type == "soql":
        return build_soql_example_prompt(
            pattern_id, pattern_name, evidence, attack_delta
        )
    if api_type == "mixed":
        return build_mixed_example_prompt(
            pattern_id, pattern_name, evidence, attack_delta, endpoint, method
        )
    return build_rest_example_prompt(
        pattern_id, pattern_name, evidence, attack_delta, endpoint, method
    )
