"""Ollama LLM client for local inference."""

import logging
import os
from typing import Optional

import httpx

from bola_ai.config import (
    LLM_CHAT_TIMEOUT_SECONDS,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_NUM_CTX,
    OLLAMA_NUM_PREDICT,
)
from bola_ai.logging_config import get_logger

logger = get_logger("llm")

def _default_num_thread() -> int:
    """Pick a sane default CPU thread count for local inference.

    Ollama auto-detection may choose very low values in constrained/containerized
    environments, which makes inference unreasonably slow.
    """
    override = os.environ.get("BOLA_AI_NUM_THREAD")
    if override is not None:
        return int(override)
    cpus = os.cpu_count() or 2
    return max(2, min(8, cpus))


_NUM_THREAD = _default_num_thread()


def chat(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: Optional[float] = None,
    num_predict: Optional[int] = None,
) -> str:
    """Send chat messages to Ollama and return the assistant reply.

    ``timeout`` is inference-only (max wait for one completion). Defaults to
    ``LLM_CHAT_TIMEOUT_SECONDS`` — do not increase to work around slow answers;
    use faster model/hardware or shorter prompts. For ingest/stack delays, use
    ``BOLA_AI_INGEST_TIMEOUT`` / ``BOLA_AI_STACK_WAIT_SECONDS`` instead.

    ``num_predict`` overrides ``OLLAMA_NUM_PREDICT`` for this call only; useful
    for startup auto-analysis which benefits from a tighter token budget.
    """
    t = LLM_CHAT_TIMEOUT_SECONDS if timeout is None else float(timeout)
    url = f"{base_url or OLLAMA_BASE_URL}/api/chat"
    options: dict = {
        "num_ctx": OLLAMA_NUM_CTX,
        "num_predict": num_predict if num_predict is not None else OLLAMA_NUM_PREDICT,
    }
    if _NUM_THREAD > 0:
        options["num_thread"] = _NUM_THREAD
    payload = {
        "model": model or OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": options,
    }
    logger.debug("POST %s model=%s num_ctx=%s num_thread=%s",
                 url, payload.get("model"), options.get("num_ctx"), options.get("num_thread"))
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
