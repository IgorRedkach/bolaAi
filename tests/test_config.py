"""Config invariants (Issue 16–17: analyze vs LLM; ingest vs inference)."""

from bola_ai import config


def test_analyze_client_timeout_covers_llm_chat_timeout():
    """POST /analyze client must not abort before Ollama chat completes (Issue 16)."""
    assert config.ANALYZE_CLIENT_TIMEOUT >= config.LLM_CHAT_TIMEOUT_SECONDS


def test_ingest_timeout_allows_learning_not_inference():
    """Ingest (embedding) may be slow; separate from LLM reply cap (Issue 17)."""
    assert config.INGEST_HTTP_TIMEOUT >= 300
    assert config.INGEST_HTTP_TIMEOUT >= config.LLM_CHAT_TIMEOUT_SECONDS


def test_stack_startup_waits_separate_from_llm():
    """Longer poll for Docker/model load; not for extending chat generation (Issue 17)."""
    assert config.STACK_READY_WAIT_SECONDS >= 120
    assert config.OLLAMA_STARTUP_PROBE_TIMEOUT >= 30
