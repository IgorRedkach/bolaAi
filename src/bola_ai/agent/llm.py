"""Ollama LLM client for local inference."""

import logging
from typing import Optional

import httpx

from bola_ai.config import OLLAMA_BASE_URL, OLLAMA_MODEL
from bola_ai.logging_config import get_logger

logger = get_logger("llm")


def chat(
    messages: list[dict[str, str]],
    *,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    timeout: float = 300.0,
) -> str:
    """Send chat messages to Ollama and return the assistant reply."""
    url = f"{base_url or OLLAMA_BASE_URL}/api/chat"
    payload = {
        "model": model or OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
    }
    logger.debug("POST %s model=%s", url, payload.get("model"))
    with httpx.Client(timeout=timeout) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()
    data = resp.json()
    msg = data.get("message")
    if not msg:
        logger.warning("Ollama returned no message")
        return ""
    return msg.get("content", "").strip()


def is_available(base_url: Optional[str] = None) -> bool:
    """Check if Ollama is reachable."""
    try:
        with httpx.Client(timeout=5.0) as client:
            r = client.get(f"{base_url or OLLAMA_BASE_URL}/api/tags")
            ok = r.status_code == 200
            logger.debug("Ollama availability: %s", ok)
            return ok
    except Exception as e:
        logger.debug("Ollama not available: %s", e)
        return False
