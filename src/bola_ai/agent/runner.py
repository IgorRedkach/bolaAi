"""Run BOLA analysis: RAG retrieval + LLM."""

import logging
import re
from typing import Optional

from bola_ai import config as cfg
from bola_ai.agent.llm import chat, is_available
from bola_ai.agent.prompts import BOLA_SYSTEM_PROMPT, build_analysis_prompt
from bola_ai.logging_config import get_logger
from bola_ai.memory import log_memory
from bola_ai.rag.store import DocStore

logger = get_logger("agent")


_BOLA_RAG_QUERY = (
    "API endpoint authorization access control object ID path resource "
    "BOLA vulnerability ownership check permission token user"
)


def run_analysis(
    store: DocStore,
    query: str = "Identify potential BOLA vulnerabilities and suggest verification steps.",
    *,
    n_context: int = 10,
    model: Optional[str] = None,
    source_filter: Optional[list[str]] = None,
    timeout: Optional[float] = None,
) -> str:
    """
    Retrieve relevant chunks from the store, build prompt, call LLM, return response.

    RAG search always uses a BOLA-focused query to find the most relevant
    chunks regardless of the user's phrasing.  The user's actual query is
    sent to the LLM as-is.

    Args:
        source_filter: if provided, only retrieve chunks from these sources
            (user documents), preventing training data contamination.
    """
    log_memory(logger, "run_analysis start")
    rag_query = _BOLA_RAG_QUERY
    logger.info("RAG search: n_context=%s rag_query_len=%s user_query_len=%s source_filter=%s",
                n_context, len(rag_query), len(query or ""), source_filter)
    context_parts = store.search(rag_query, n_results=n_context, source_filter=source_filter)
    if query and query != rag_query:
        extra = store.search(query, n_results=max(n_context // 2, 5), source_filter=source_filter)
        seen_content = {p["content"] for p in context_parts if p.get("content")}
        for p in extra:
            if p.get("content") and p["content"] not in seen_content:
                context_parts.append(p)
                seen_content.add(p["content"])
    context = "\n\n".join(
        p["content"] for p in context_parts if p.get("content")
    ).strip()
    max_chars = getattr(cfg, "MAX_CONTEXT_CHARS", 0)
    if max_chars and len(context) > max_chars:
        context = context[:max_chars] + "\n\n[... context truncated for memory ...]"
        logger.info("RAG: truncated context to %s chars", max_chars)
    logger.info("RAG: retrieved %s chunks, context_len=%s", len(context_parts), len(context))

    user_prompt = build_analysis_prompt(context, query=query)
    messages = [
        {"role": "system", "content": BOLA_SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    logger.info("Calling LLM (model=%s) ...", model or "default")
    out = chat(messages, model=model, timeout=timeout)
    log_memory(logger, "after LLM chat")
    allowed_paths = _extract_paths_from_context(context)
    out = _normalize_report(out or "", allowed_paths=allowed_paths, context=context, source_filter=source_filter)
    logger.info("LLM response length=%s", len(out or ""))
    return out


def _context_indicates_rest_only_no_graphql(context: str) -> bool:
    """True when doc explicitly excludes GraphQL (REST-only APIs).

    Returns False (preserve GraphQL) whenever the context itself contains
    actual GraphQL operations, Salesforce Aura/Lightning, or HAR JSON —
    these legitimately include GraphQL content.
    """
    if not context or not context.strip():
        return False
    c = context.lower()
    # If context contains actual GraphQL operations or Salesforce platform markers,
    # it legitimately includes GraphQL — don't strip it.
    if any(kw in c for kw in ("query {", "mutation {", "graphql", "aura", "lightning.force")):
        # Still honor explicit "no graphql" phrasing when present.
        if "no graphql" in c:
            return True
        return False

    # Explicit exclusion checks for truly REST-only excerpts.
    if "no graphql" in c or "rest only" in c or "rest-only" in c:
        return True
    return False


def _strip_invented_graphql_blocks(report: str) -> str:
    """Replace ```graphql blocks with REST reminder (doc has no GraphQL)."""
    note = (
        "*Use the documented REST paths with curl (two Bearer tokens); "
        "this excerpt does not define GraphQL operations.*"
    )

    def _repl(_m: re.Match[str]) -> str:
        return note

    return re.sub(r"```(?:graphql|gql)\s*\n[\s\S]*?```", _repl, report, flags=re.IGNORECASE)


def _strip_report_leakage(report: str) -> str:
    """Strip knowledge-base and system-prompt content that the model pastes verbatim into the report."""
    # WP-006: BOLA Remediation Cheat Sheet from bola_patterns.md leaks as a trailing block.
    # WP-016: GROUNDING_USER_SUFFIX from the user prompt is echoed verbatim by the model.
    for marker in (
        "## BOLA Remediation Cheat Sheet",
        "## Remediation Cheat Sheet",
        "**BOLA Remediation Cheat Sheet",
        "**Mandatory grounding (person-style and runbook answers included):**",
        "**Mandatory grounding:",
    ):
        idx = report.find(marker)
        if idx >= 0:
            report = report[:idx].rstrip()


    # WP-008 / WP-013: Raw "## Notes" / "### Notes" / "### N. Notes" fixture sections
    # leak mid-report as spurious findings. Strip from heading to next equal/higher heading.
    report = re.sub(
        r"\n#{2,3}\s+(?:\d+\.\s+)?Notes\b.*?(?=\n#{1,3}\s|\Z)",
        "\n",
        report,
        flags=re.IGNORECASE | re.DOTALL,
    )

    # WP-011: Hallucinated "bypass" query parameters in curl URL examples.
    # Strip ?owner=...&tenant=...&admin=...&uuid=... patterns not found in the documentation.
    report = re.sub(
        r"\?(?:owner|tenant|admin|uuid|user_id|account_id|org_id)=[^\"' \t\n\)]+(?:&[^\"' \t\n\)]+)*",
        "",
        report,
        flags=re.IGNORECASE,
    )

    # WP-012: Python / Django / Express implementation code blocks — off-topic fix code.
    # Strip fenced code blocks that contain function definitions or ORM patterns.
    # Uses a non-backtracking approach: find fenced blocks then test content separately.
    def _strip_impl_code_block(m: re.Match) -> str:
        block = m.group(0)
        if any(p in block for p in ("def ", "class ", ".objects.", "if request.", "import ")):
            return ""
        return block

    report = re.sub(r"```[a-zA-Z]*\n[\s\S]*?```", _strip_impl_code_block, report)

    # Note: "Additional Notes" sections are preserved — they often contain
    # valuable HAR/Salesforce observations the model extracted from the doc.

    return report


def _is_structured_content(context: str, source_filter: Optional[list[str]] = None) -> bool:
    """Detect HAR, Salesforce, GraphQL, or JSON-based content that needs relaxed normalization."""
    if source_filter:
        for s in source_filter:
            sl = s.lower()
            if any(kw in sl for kw in ("har", "json", "salesforce", "aura")):
                return True
    if context:
        c = context.lower()
        if any(kw in c for kw in (
            "har api capture", "aura", "lightning.force",
            "salesforce", "query {", "mutation {", '"method"',
            "graphql query:", "getrecordwithfields", "updaterecord",
        )):
            return True
    return False


def _normalize_report(
    report: str, *, allowed_paths: Optional[list[str]] = None, context: str = "",
    source_filter: Optional[list[str]] = None,
) -> str:
    """Normalize LLM output: fix duplicate headings (Issue 4), verification hint (Issue 5), redact hallucinated endpoints."""
    if not report.strip():
        return report
    structured = _is_structured_content(context, source_filter)
    report = _strip_report_leakage(report)
    if _context_indicates_rest_only_no_graphql(context):
        report = _strip_invented_graphql_blocks(report)
    # Issue 4: Replace "#### ### " or "### ### " with "### " so each finding has one ### heading
    report = re.sub(r"#{3,6}\s*###\s*", "### ", report)
    # Issue 8: Replace "**### Title**" or "**### Title" with "**Title**" (bold wrapped around heading markers)
    report = re.sub(r"\*\*\s*###\s*", "**", report)
    # Fix "**Title**# **Label:**" → "**Title**\n\n**Label:**"  (GraphQL heading bleed-through)
    report = re.sub(r"\*\*\s*#\s*\*\*", "**\n\n**", report)
    if not structured:
        # Redact users/tenants endpoints only when they are not in allowed documented paths.
        if allowed_paths:
            users_tenants_regexes = [_path_pattern_to_regex(p) for p in allowed_paths]

            def _replace_unknown_users_tenants(match: re.Match) -> str:
                token = (match.group(2) or "").strip("`")
                if any(rx.fullmatch(token) for rx in users_tenants_regexes):
                    return match.group(0)
                return "[use only endpoints from the documentation]"

            report = re.sub(
                r"(GET|POST|PUT|DELETE)?\s*(`?/api/[^`\s]*(?:users|tenants)[^`\s]*`?)",
                _replace_unknown_users_tenants,
                report,
                flags=re.IGNORECASE,
            )
        else:
            report = re.sub(
                r"(GET|POST|PUT|DELETE)?\s*(`?/api/[^`\s]*(?:users|tenants)[^`\s]*`?)",
                "[use only endpoints from the documentation]",
                report,
                flags=re.IGNORECASE,
            )
        report = re.sub(
            r"using the `/api/users` endpoint|obtain a token using the `/api/users` endpoint|`/api/users` endpoint",
            "using an auth endpoint from the documentation",
            report,
            flags=re.IGNORECASE,
        )
    # Issue 6: BOLA verification requires two authenticated users, not "without a token"
    report = re.sub(
        r"\bwithout a token\b",
        "with two different user tokens (e.g. token A and token B)",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"\bwithout authentication\b(?!\s*;?\s*that)",
        "with two different authenticated users",
        report,
        flags=re.IGNORECASE,
    )
    # WP-018: Inverted rationale — model writes "The server restricts this endpoint to [role]"
    # (positive/secure assertion) instead of "No documentation states the server restricts this."
    # Catch immediately after a Rationale heading (### Rationale: or **Rationale:**).
    report = re.sub(
        r"(?m)^(#{1,4}\s+Rationale:\s*|(?:\*\*)?Rationale:(?:\*\*)?\s+)The server\s+(restricts|requires|enforces|ensures|validates|checks)\b",
        r"\1No documentation states the server \2",
        report,
        flags=re.IGNORECASE,
    )
    # WP-019: Strip -d body payloads containing submittingEmployeeId from GET/HEAD curl examples
    # (model over-applies body-field BOLA pattern to path-level GET endpoints).
    def _strip_get_body_payload(m: re.Match) -> str:
        block = m.group(0)
        # Only strip if this is a GET or HEAD curl
        if not re.search(r"\bcurl\s+-X\s+(?:GET|HEAD)\b", block, re.IGNORECASE):
            return block
        # Strip -d '...' or --data '...' arguments containing submittingEmployeeId
        block = re.sub(
            r"\s+-d\s+'[^']*submittingEmployeeId[^']*'",
            "",
            block,
            flags=re.IGNORECASE,
        )
        block = re.sub(
            r'\s+--data\s+"[^"]*submittingEmployeeId[^"]*"',
            "",
            block,
            flags=re.IGNORECASE,
        )
        return block
    report = re.sub(r"```[a-z]*\n[\s\S]*?```", _strip_get_body_payload, report)
    # WP-020: Strip repeated #### Rationale: / #### Verification steps: sub-blocks after the first
    # occurrence within each ### finding section.
    def _dedup_subheadings(report_text: str) -> str:
        # Find all ### (exactly 3 hashes) heading positions using MULTILINE ^ anchor.
        heading_starts = [m.start() for m in re.finditer(r"(?m)^#{3}(?!#)", report_text)]
        if not heading_starts:
            return report_text
        # Process text before first heading, then each section.
        boundaries = heading_starts + [len(report_text)]
        pre_heading = report_text[: heading_starts[0]]
        result = [pre_heading]
        for i, start in enumerate(heading_starts):
            end = boundaries[i + 1]
            section = report_text[start:end]
            # Strip duplicate #### sub-headings within this finding section.
            seen: set[str] = set()
            def _dedup_sub(m: re.Match, _seen: set = seen) -> str:
                # Key is only the heading line (first line), not the body — so two
                # "#### Rationale:" blocks with different bodies are still duplicates.
                heading_line = m.group(0).split("\n", 1)[0].lower().strip()
                if heading_line in _seen:
                    return ""
                _seen.add(heading_line)
                return m.group(0)
            # Match the sub-heading plus all its content (until the next #### or ### or end).
            section = re.sub(
                r"(?m)^(####\s+(?:Rationale|Verification steps?)[^\n]*\n(?:(?!^#{3,4}\s).*\n?)*)",
                _dedup_sub,
                section,
                flags=re.IGNORECASE,
            )
            result.append(section)
        return "".join(result)
    report = _dedup_subheadings(report)
    # WP-023: Strip duplicate ### finding sections (same heading text repeated).
    # The 1.5B model often loops and emits the same finding 3-4x.
    def _dedup_findings(report_text: str) -> str:
        heading_positions = [m.start() for m in re.finditer(r"(?m)^###\s", report_text)]
        if not heading_positions:
            return report_text
        prefix = report_text[: heading_positions[0]]
        boundaries = heading_positions + [len(report_text)]
        seen: set[str] = set()
        kept: list[str] = [prefix]
        for i in range(len(heading_positions)):
            section = report_text[boundaries[i] : boundaries[i + 1]]
            heading_line = section.split("\n", 1)[0].strip().lower()
            heading_line = re.sub(r"\*+", "", heading_line).strip()
            if heading_line in seen:
                continue
            seen.add(heading_line)
            kept.append(section)
        return "".join(kept)
    report = _dedup_findings(report)
    # WP-015: "Call with an invalid token" tests authentication, not BOLA.
    # Replace with the correct two-valid-user phrasing.
    report = re.sub(
        r"\bwith (?:the same endpoint with )?an invalid token\b",
        "with token B (a different valid user token)",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"\bCall the same endpoint with an invalid token\b",
        "Call the same endpoint with token B (a different valid user token)",
        report,
        flags=re.IGNORECASE,
    )
    # Issue 9: Fix logically invalid verification conclusions based on 404/not-found outcomes.
    report = re.sub(
        r"if both (?:requests?\s*)?(?:receive|return)\s+(?:a\s+)?404(?:\s+error)?[,;]?\s*bola is confirmed",
        "if both requests return 404, the object may not exist; BOLA is not confirmed. Use an existing object ID owned by user A and retest with user B.",
        report,
        flags=re.IGNORECASE,
    )
    # Issue 11: Authentication failures (401/invalid token) do not confirm BOLA.
    report = re.sub(
        r"if (?:the )?endpoint responds with (?:a )?401[^.]*bola is confirmed",
        "if the endpoint responds with 401 Unauthorized, authentication is enforced; this does not confirm BOLA. Retest using two valid user tokens on the same existing object ID.",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"if (?:called|calling)?[^.]*invalid token[^.]*bola is confirmed",
        "invalid-token failure indicates authentication behavior, not BOLA confirmation. Use two valid user tokens and compare access to the same object ID.",
        report,
        flags=re.IGNORECASE,
    )
    # Fix "if both receive data, BOLA is not verified" — inverted conclusion.
    report = re.sub(
        r"if both receive data,\s*(?:it )?indicates? that bola is not verified",
        "if both receive data for the same object ID, BOLA is confirmed (object-level authorization may be missing)",
        report,
        flags=re.IGNORECASE,
    )
    # Fix "if only one response is received, BOLA is confirmed" — incorrect logic.
    report = re.sub(
        r"if only one response is received,\s*bola is confirmed",
        "if only one user receives data for a resource owned by the other, investigate the ownership model further",
        report,
        flags=re.IGNORECASE,
    )
    # Clarify secure interpretation: A=200 and B=403 suggests proper ownership enforcement.
    report = re.sub(
        r"if token a'?s call returns 200 and token b'?s call returns 403[^.]*\.",
        "if token A returns 200 and token B returns 403 for the same object ID, access control appears to be enforced (this outcome does not confirm BOLA).",
        report,
        flags=re.IGNORECASE,
    )
    # 403 for unauthorized user is generally secure enforcement, not a vulnerability outcome.
    report = re.sub(
        r"Vulnerable Outcome\s*\(\s*403\s+Forbidden\s*\)",
        "Secure Outcome (403 Forbidden)",
        report,
        flags=re.IGNORECASE,
    )
    # Invalid confirmation from user A denied/missing data is not BOLA proof.
    report = re.sub(
        r"if (?:alice|user a)[^.]*does not receive data[^.]*bola is confirmed",
        "if user A does not receive data, verify the object exists and that user A is authorized; this alone does not confirm BOLA.",
        report,
        flags=re.IGNORECASE,
    )
    # Issues 12/13: GraphQL verification that says "token without required permissions"
    # is testing auth, not BOLA. Replace with two-valid-user-token phrasing.
    report = re.sub(
        r"(?:use|with) a token that does not have (?:the )?required permissions",
        "use two different valid user tokens (token A for user A, token B for user B)",
        report,
        flags=re.IGNORECASE,
    )
    # "Token with read permission" vs "token without read permission" tests auth, not BOLA.
    report = re.sub(
        r"with a user token that has the `read` permission\.?\s*2\.\s*Call[^.]*with a user token that does not have the `read` permission",
        "with token A (user A) and then with token B (user B); if both receive data for the same object ID, BOLA is confirmed",
        report,
        flags=re.IGNORECASE | re.DOTALL,
    )
    report = re.sub(
        r"user token that (?:does not have|without) (?:the )?`?read`? permission",
        "second user token (user B)",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"user token that has the `?read`? permission",
        "user token (e.g. token A)",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"verify that the (?:mutation|query|operation) (?:or query )?returns an error indicating that the caller is not authorized",
        "verify that user B cannot access user A's data (BOLA, not auth check)",
        report,
        flags=re.IGNORECASE,
    )
    # Issue 16: Bearer in URL query string is incorrect; auditors must use Authorization header
    report = re.sub(
        r"\?token=Bearer[^\s`\"'\)]*",
        ' with -H "Authorization: Bearer <token>"',
        report,
        flags=re.IGNORECASE,
    )
    # Wrong HTTP method: doc describes GET but model sometimes emits POST for same path
    report = re.sub(
        r"\bPOST\s+(`?/api/v2/participants(?:/\{participantId\}|/[\w\-{}]+)`?)",
        r"GET \1",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"\bPOST\s+(`?/api/v2/sites/[\w\-{}]+/randomization-log`?)",
        r"GET \1",
        report,
        flags=re.IGNORECASE,
    )
    # Issue 10: Ground endpoint suggestions to ingested context (avoid unrelated endpoint drift).
    # Skip for HAR/JSON/Salesforce/GraphQL contexts where path extraction is unreliable.
    allowed_paths = allowed_paths or []
    if allowed_paths and not structured:
        allowed_regexes = [_path_pattern_to_regex(p) for p in allowed_paths]

        def _replace_unknown_path(match: re.Match) -> str:
            token = match.group(0)
            if any(rx.fullmatch(token) for rx in allowed_regexes):
                return token
            return "[use only endpoints from the documentation]"

        report = re.sub(
            r"/[A-Za-z0-9._{}\-]+(?:/[A-Za-z0-9._{}\-]+)+",
            _replace_unknown_path,
            report,
        )
        # If URL path redaction produced broken curl examples, inject a grounded placeholder URL.
        fallback_path = allowed_paths[0]
        report = re.sub(
            r"https?://\s*\[use only endpoints from the documentation\]",
            f"https://api.example.com{fallback_path}",
            report,
            flags=re.IGNORECASE,
        )
        report = re.sub(
            r"https?:/\[use only endpoints from the documentation\]",
            f"https://api.example.com{fallback_path}",
            report,
            flags=re.IGNORECASE,
        )
        # Repair placeholder-only path fields so runbooks remain actionable.
        report = re.sub(
            r"(?im)^(\s*[-*]?\s*Path:\s*)\[use only endpoints from the documentation\]\s*$",
            rf"\1{fallback_path}",
            report,
        )
    # Redact known hallucinated path prefixes — only for plain REST docs.
    # For HAR/Salesforce/GraphQL contexts this is too aggressive and can hide real paths.
    hallucinated_prefixes = (
        "/api/v1/patients", "/api/v1/documents", "/api/v1/orders", "/api/v1/prescriptions",
        "/api/internal/cases", "/api/users",
        "/api/patients", "/api/documents", "/api/adjustments", "/api/invoices",
        "/api/orders", "/api/payments", "/api/billing", "/api/auditlogs",
        "/api/v2/patients", "/api/v2/documents", "/api/v2/payouts", "/api/v2/invoicing", "/api/v2/audit",
        "/api/statuses",
        "/api/v2/applications", "/api/v2/funds", "/api/v2/transactions",
        "/api/loans",
    )
    if not structured:
        for prefix in hallucinated_prefixes:
            if not any(p.lower().startswith(prefix.lower()) for p in allowed_paths):
                report = re.sub(
                    re.escape(prefix) + r"[^\s\]`]*",
                    "[use only endpoints from the documentation]",
                    report,
                    flags=re.IGNORECASE,
                )
        # Replace hallucinated finding titles when those resources are not in the doc
        doc_resources_lower = " ".join(p.lower() for p in allowed_paths)
        if "patient" not in doc_resources_lower and "patients" not in doc_resources_lower:
            report = re.sub(r"\bPatient API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "document" not in doc_resources_lower and "documents" not in doc_resources_lower:
            report = re.sub(r"\bDocument API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if not any(p.lower().startswith("/api/users") for p in allowed_paths):
            report = re.sub(r"\bUser API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "order" not in doc_resources_lower and "orders" not in doc_resources_lower:
            report = re.sub(r"\bOrder API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "adjustment" not in doc_resources_lower and "adjustments" not in doc_resources_lower:
            report = re.sub(r"\bAdjustment API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "payment" not in doc_resources_lower and "payments" not in doc_resources_lower:
            report = re.sub(r"\bPayment API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "billing" not in doc_resources_lower:
            report = re.sub(r"\bBilling API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
        if "audit" not in doc_resources_lower and "auditlog" not in doc_resources_lower:
            report = re.sub(r"\bAudit Log API\b", "Endpoint from documentation", report, flags=re.IGNORECASE)
    # Fix malformed heading when path in ### title was redacted (e.g. "### 4.[use only endpoints...]")
    report = re.sub(r"(###\s*\d*\.)\s*\[use only endpoints from the documentation\]", r"\1 Endpoint from documentation", report)
    # WP-017: Strip entire finding sections whose heading itself was redacted.
    # E.g. "### GET [use only endpoints...]" → the whole block is a hallucinated finding — remove it.
    # Apply twice to catch consecutive blocks (re.sub processes left-to-right in one pass).
    _redacted_heading_block = re.compile(
        r"^#{3,4}\s+(?:\*\*)?(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)?\s*"
        r"\[use only endpoints from the documentation\][^\n]*\n"
        r"(?:(?!^#{3,4}\s).*\n)*",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    report = _redacted_heading_block.sub("", report)
    report = _redacted_heading_block.sub("", report)  # second pass for consecutive blocks
    # In path-audit style responses, drop placeholder-only NO lines.
    report = re.sub(
        r"(?im)^\s*-\s*\*\*NO\*\*\s*(?:[A-Z]+\s+)?\[use only endpoints from the documentation\]\s*$\n?",
        "",
        report,
    )
    # WP-010 partial mitigation: fix curl blocks that use the wrong documented path.
    report = _fix_curl_path_mismatch(report, allowed_paths or [])
    # Issue 5: Ensure verification unambiguously mentions two different user tokens (append if missing or vague)
    two_token_phrases = [
        "two different user tokens", "two different users", "two user tokens",
        "token a", "token b", "with two different", "two tokens",
        "another user token", "one user token", "second user token",
    ]
    report_lower = report.lower()
    has_unambiguous_two = any(p in report_lower for p in two_token_phrases)
    if "potential findings" in report_lower and ("verification" in report_lower or "### " in report_lower) and not has_unambiguous_two:
        report = report.rstrip() + "\n\n**Verification reminder:** To confirm BOLA, call the same endpoint with two different user tokens (e.g. user A and user B); if both receive data for the same object ID, object-level authorization may be missing.\n"
    # Remove dangling trailing finding headings before reminder blocks (e.g. "### GET /api").
    report = re.sub(
        r"\n###\s+[^\n]+(?:\n\s*){1,3}(?=\*\*Verification reminder:\*\*)",
        "\n",
        report,
        flags=re.IGNORECASE,
    )
    # Strip generic meta headings that are not real endpoint findings.
    report = re.sub(
        r"^\s*###\s+Potential BOLA findings with rationale and verification steps\s*$\n?",
        "",
        report,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    report = re.sub(
        r"^\s*####\s+.*one-time e2e fixture.*$\n?",
        "",
        report,
        flags=re.IGNORECASE | re.MULTILINE,
    )
    # Remove dangling trailing code fence when generation was cut mid-block.
    if report.count("```") % 2 == 1:
        report = re.sub(r"\n?```[\t ]*$", "", report.rstrip(), flags=re.MULTILINE)
    # Guarantee a minimal actionable body instead of near-empty "Potential findings" shells.
    if len(report.strip()) < 60 and "potential findings" in report.lower():
        report = (
            report.rstrip()
            + "\n\nNo grounded finding could be reliably extracted from this response. "
            "Re-run analysis with a narrower endpoint-focused query and verify with two different user tokens.\n"
        )
    return report


_DOMAIN_SEGMENT_RE = re.compile(r"\.[a-zA-Z]{2,}")  # e.g. ".gov", ".com", ".internal"
_HEADING_PATH_RE = re.compile(
    # Try multi-segment first (/a/b/c), fall back to single meaningful segment (≥4 chars after /)
    r"(/[A-Za-z0-9_{}\-]+(?:/[A-Za-z0-9_{}\-]+)+|/[A-Za-z0-9_{}\-]{4,})"
)
_CURL_URL_RE = re.compile(r'https?://[^\s"\'`\)]+')


def _extract_heading_path(heading_line: str) -> Optional[str]:
    """Extract the first API path from a ### heading (e.g. '/accounts/{accountId}/usage')."""
    m = _HEADING_PATH_RE.search(heading_line)
    if not m:
        return None
    first_seg = m.group(1).lstrip("/").split("/")[0]
    if _DOMAIN_SEGMENT_RE.search(first_seg):
        return None
    return m.group(1)


def _fix_curl_path_mismatch(report: str, allowed_paths: list[str]) -> str:
    """WP-010 partial mitigation: strip fenced curl blocks whose URL path does not match
    the path in their finding's ### heading, replacing them with a corrective note.

    Only fires when:
    - The heading clearly names an endpoint path (e.g. ``### PATCH /accounts/{accountId}/contact``).
    - The curl block contains a URL whose path is a **different** documented allowed path
      (i.e. the model reused the first retrieved path for all findings).
    - Conservative: does NOT strip if URL is already redacted or if no allowed_paths given.
    """
    if not allowed_paths:
        return report

    allowed_regexes = [_path_pattern_to_regex(p) for p in allowed_paths]

    def _path_matches(pattern: str, url: str) -> bool:
        rx = _path_pattern_to_regex(pattern)
        # Check if the URL contains the pattern path anywhere
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return bool(rx.search(parsed.path))
        except Exception:
            return True  # Don't strip on parse error

    def _url_is_documented(url: str) -> bool:
        """True if the URL's path matches any allowed path pattern."""
        from urllib.parse import urlparse
        try:
            parsed_path = urlparse(url).path
        except Exception:
            return False
        return any(rx.search(parsed_path) for rx in allowed_regexes)

    # Split report at heading boundaries; process each section
    parts = re.split(r"(#{3,4}[^\n]+)", report)
    result: list[str] = []
    current_path: Optional[str] = None
    current_path_explicit: bool = False  # True only when heading named the path directly

    for part in parts:
        heading_match = re.match(r"#{3,4}[^\n]+", part)
        if heading_match:
            extracted = _extract_heading_path(part)
            if extracted is not None:
                # Heading explicitly names an endpoint path.
                current_path = extracted
                current_path_explicit = True
            elif re.match(r"###(?!#)", part):
                # Top-level finding heading (###) with no endpoint path (e.g. "### Companies").
                # Reset — we don't know which endpoint this section covers.
                current_path_explicit = False
            # else: sub-heading (####) with no path — inherit current_path_explicit from parent ###.
            result.append(part)
            continue

        if not current_path or not current_path_explicit:
            result.append(part)
            continue

        def _check_block(m: re.Match) -> str:
            block = m.group(0)
            if "[use only endpoints" in block:
                return block  # already redacted; don't touch
            urls = _CURL_URL_RE.findall(block)
            if not urls:
                return block
            for url in urls:
                if not _url_is_documented(url):
                    return block  # URL not documented; let other rules handle
                if not _path_matches(current_path, url):
                    # Wrong documented path for this finding — strip the block
                    method_m = re.search(r"\bcurl\s+-X\s+(\w+)\b", block, re.IGNORECASE)
                    method = method_m.group(1).upper() if method_m else "GET"
                    return (
                        f"```sh\n"
                        f"# {method} {current_path}  (use the exact path above with your base URL)\n"
                        f'curl -X {method} "https://api.example.com{current_path}" '
                        f'-H "Authorization: Bearer <tokenA>"\n'
                        f'curl -X {method} "https://api.example.com{current_path}" '
                        f'-H "Authorization: Bearer <tokenB>"\n'
                        f"```"
                    )
            return block

        part = re.sub(r"```[a-z]*\n[\s\S]*?```", _check_block, part)
        result.append(part)

    return "".join(result)


def _extract_paths_from_context(context: str) -> list[str]:
    """Extract endpoint-like paths from retrieved context.

    Includes single-segment meaningful paths (e.g. ``/coverage-changes``) in
    addition to multi-segment paths.  Excludes domain-like segments (WP-009)
    and very short or version-only segments like ``/v2``.
    """
    if not context:
        return []
    # Match single-segment paths (≥4 chars after /) and multi-segment paths.
    paths = re.findall(
        r"/[A-Za-z0-9._{}\-]{4,}(?:/[A-Za-z0-9._{}\-]+)*|"
        r"/[A-Za-z0-9._{}\-]+(?:/[A-Za-z0-9._{}\-]+)+",
        context,
    )
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        if len(p) < 4:
            continue
        # Skip paths whose first segment looks like a domain (e.g. /api.example.com/v2)
        first_seg = p.lstrip("/").split("/")[0]
        if _DOMAIN_SEGMENT_RE.search(first_seg):
            continue
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _path_pattern_to_regex(path_pattern: str) -> re.Pattern[str]:
    """Convert path with {param} placeholders into a matching regex."""
    esc = re.escape(path_pattern)
    esc = re.sub(r"\\\{[^\\\}]+\\\}", r"[^/]+", esc)
    return re.compile(esc)


def analyze_for_bola(
    store: DocStore,
    custom_query: Optional[str] = None,
    n_context: Optional[int] = None,
    source_filter: Optional[list[str]] = None,
    timeout: Optional[float] = None,
) -> str:
    """Convenience: run BOLA-focused analysis with default or custom query."""
    k = cfg.N_CONTEXT if n_context is None else n_context
    query = custom_query or "Identify potential BOLA vulnerabilities and suggest verification steps."
    return run_analysis(store, query=query, n_context=k, source_filter=source_filter, timeout=timeout)
