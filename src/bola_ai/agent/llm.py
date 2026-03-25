"""Ollama LLM client for local inference."""

import logging
from typing import Optional

import httpx

from bola_ai.config import LLM_CHAT_TIMEOUT_SECONDS, OLLAMA_BASE_URL, OLLAMA_MODEL
from bola_ai.logging_config import get_logger

logger = get_logger("llm")


def chat(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: Optional[float] = None,
) -> str:
    """Send chat messages to Ollama and return the assistant reply.

    ``timeout`` is inference-only (max wait for one completion). Defaults to
    ``LLM_CHAT_TIMEOUT_SECONDS`` — do not increase to work around slow answers;
    use faster model/hardware or shorter prompts. For ingest/stack delays, use
    ``BOLA_AI_INGEST_TIMEOUT`` / ``BOLA_AI_STACK_WAIT_SECONDS`` instead.
    """
    t = LLM_CHAT_TIMEOUT_SECONDS if timeout is None else float(timeout)
    url = f"{base_url or OLLAMA_BASE_URL}/api/chat"
    payload = {
        "model": model or OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {
            # Allow up to 2048 output tokens so multi-finding reports are not truncated.
            "num_predict": 2048,
        },
    }
    logger.debug("POST %s model=%s", url, payload.get("model"))
    with httpx.Client(timeout=t) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
    data = resp.json()
    msg = data.get("message")
    if not msg:
        logger.warning("Ollama returned no message")
        return ""
    return msg.get("content", "").strip()


def is_available(base_url: Optional[str] = None) -> bool:
    """Check if Ollama is reachable (startup probe; not chat inference)."""
    from bola_ai.config import OLLAMA_STARTUP_PROBE_TIMEOUT

    try:
        with httpx.Client(timeout=OLLAMA_STARTUP_PROBE_TIMEOUT) as client:
            r = client.get(f"{base_url or OLLAMA_BASE_URL}/api/tags")
            ok = r.status_code == 200
            logger.debug("Ollama availability: %s", ok)
            return ok
    except Exception as e:
        logger.debug("Ollama not available: %s", e)
        return False
