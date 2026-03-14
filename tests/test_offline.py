"""Tests that the tool does not require or use the open internet at runtime."""
import pytest
from bola_ai import config


def test_ollama_url_is_local_or_internal():
    """Ollama must be localhost or internal host (no public internet)."""
    url = config.OLLAMA_BASE_URL or ""
    assert url, "OLLAMA_BASE_URL should be set"
    lower = url.lower()
    # localhost, 127.0.0.1, or docker-style host (e.g. http://ollama:11434)
    assert (
        "localhost" in lower
        or "127.0.0.1" in lower
        or "ollama:" in lower
        or lower.startswith("http://ollama")
    ), f"OLLAMA_BASE_URL should be local/internal, got {url}"


def test_no_external_host_in_config():
    """Config should not reference external domains (huggingface, api.*, etc.)."""
    # Default embedding model name is local/cacheable; not a URL
    emb = getattr(config, "EMBEDDING_MODEL", "") or ""
    assert not emb.startswith("http"), "Embedding model should not be a URL"
    assert "api." not in emb or "localhost" in emb, "No external API in default config"
