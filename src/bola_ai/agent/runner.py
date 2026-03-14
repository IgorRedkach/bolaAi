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


def run_analysis(
    store: DocStore,
    query: str = "Identify potential BOLA vulnerabilities and suggest verification steps.",
    *,
    n_context: int = 10,
    model: Optional[str] = None,
) -> str:
    """
    Retrieve relevant chunks from the store, build prompt, call LLM, return response.
    """
    log_memory(logger, "run_analysis start")
    logger.info("RAG search: n_context=%s query_len=%s", n_context, len(query or ""))
    context_parts = store.search(query, n_results=n_context)
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
    out = chat(messages, model=model)
    log_memory(logger, "after LLM chat")
    allowed_paths = _extract_paths_from_context(context)
    out = _normalize_report(out or "", allowed_paths=allowed_paths)
    logger.info("LLM response length=%s", len(out or ""))
    return out


def _normalize_report(report: str, *, allowed_paths: Optional[list[str]] = None) -> str:
    """Normalize LLM output: fix duplicate headings (Issue 4), verification hint (Issue 5), redact hallucinated endpoints."""
    if not report.strip():
        return report
    # Issue 4: Replace "#### ### " or "### ### " with "### " so each finding has one ### heading
    report = re.sub(r"#{3,6}\s*###\s*", "### ", report)
    # Issue 8: Replace "**### Title**" or "**### Title" with "**Title**" (bold wrapped around heading markers)
    report = re.sub(r"\*\*\s*###\s*", "**", report)
    # Fix "**Title**# **Label:**" → "**Title**\n\n**Label:**"  (GraphQL heading bleed-through)
    report = re.sub(r"\*\*\s*#\s*\*\*", "**\n\n**", report)
    # Redact common hallucinated endpoints not in typical doc: /api/users/, /api/tenants (any path containing these)
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
    # Issues 12/13: GraphQL verification that says "token without required permissions"
    # is testing auth, not BOLA. Replace with two-valid-user-token phrasing.
    report = re.sub(
        r"(?:use|with) a token that does not have (?:the )?required permissions",
        "use two different valid user tokens (token A for user A, token B for user B)",
        report,
        flags=re.IGNORECASE,
    )
    report = re.sub(
        r"verify that the (?:mutation|query|operation) (?:or query )?returns an error indicating that the caller is not authorized",
        "verify that user B cannot access user A's data (BOLA, not auth check)",
        report,
        flags=re.IGNORECASE,
    )
    # Redact paths containing users/tenants (e.g. /api/v1/tenants/123/users) not typically in doc
    report = re.sub(
        r"/api/[^\s`]*(?:users|tenants)[^\s`]*",
        "[use only endpoints from the documentation]",
        report,
        flags=re.IGNORECASE,
    )
    # Issue 10: Ground endpoint suggestions to ingested context (avoid unrelated endpoint drift).
    if allowed_paths:
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
    return report


def _extract_paths_from_context(context: str) -> list[str]:
    """Extract endpoint-like paths from retrieved context."""
    if not context:
        return []
    paths = re.findall(r"/[A-Za-z0-9._{}\-]+(?:/[A-Za-z0-9._{}\-]+)+", context)
    # Keep unique order, drop obvious placeholders too short to be useful.
    out: list[str] = []
    seen: set[str] = set()
    for p in paths:
        if len(p) < 4:
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
) -> str:
    """Convenience: run BOLA-focused analysis with default or custom query."""
    k = cfg.N_CONTEXT if n_context is None else n_context
    query = custom_query or "Identify potential BOLA vulnerabilities and suggest verification steps."
    return run_analysis(store, query=query, n_context=k)
