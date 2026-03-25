"""Pytest fixtures: in-memory store and API client.

Tests do NOT wipe or delete Docker containers or volumes. Wipe/teardown is only
tested when explicitly exercising that behavior (see goals: do not wipe on every run).
"""
import os
import resource
import tempfile
from pathlib import Path

_MEM_LIMIT_GB = int(os.environ.get("BOLA_AI_TEST_MEM_LIMIT_GB", "10"))
_soft, _hard = resource.getrlimit(resource.RLIMIT_AS)
_limit_bytes = _MEM_LIMIT_GB * 1024 * 1024 * 1024
if _hard == resource.RLIM_INFINITY or _hard > _limit_bytes:
    resource.setrlimit(resource.RLIMIT_AS, (_limit_bytes, _limit_bytes))


def _rss_mb():
    try:
        s = Path("/proc/self/status").read_text()
        for line in s.splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except Exception:
        pass
    return 0


def pytest_sessionstart(session):
    if session.config.getoption("--no-memory", default=False):
        return
    print(f"\n[memory] tool (pytest) session start: RSS {_rss_mb():.2f} MB")


def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--no-memory", default=False):
        return
    print(f"\n[memory] tool (pytest) session end: RSS {_rss_mb():.2f} MB")


def pytest_addoption(parser):
    parser.addoption("--no-memory", action="store_true", help="Disable memory printing")


import pytest
from fastapi.testclient import TestClient

from bola_ai.api.app import create_app
from bola_ai.rag.store import DocStore
from bola_ai.rag.fake_embedder import FakeEmbedder


@pytest.fixture
def temp_data_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def store(temp_data_dir):
    return DocStore(
        persist_directory=temp_data_dir,
        collection_name="test_collection",
        embedder=FakeEmbedder(),
    )


@pytest.fixture
def client(temp_data_dir):
    """Test client with overridden data dir and fake embedder (no heavy deps)."""
    import bola_ai.api.app as app_mod
    app_mod._store = None
    import bola_ai.config as config
    orig_path = config.CHROMA_PATH
    orig_fake = getattr(config, "USE_FAKE_EMBEDDER", False)
    config.CHROMA_PATH = temp_data_dir
    config.USE_FAKE_EMBEDDER = True
    try:
        app = create_app()
        with TestClient(app) as c:
            yield c
    finally:
        config.CHROMA_PATH = orig_path
        config.USE_FAKE_EMBEDDER = orig_fake
        app_mod._store = None


# --- Live E2E is mandatory when any of these files are collected (docs/E2E_TESTING.md) ---
_LIVE_E2E_FILES = ("test_e2e_llm.py", "test_issues_resolved.py", "test_api_live.py")


def _live_stack_reachable() -> bool:
    import httpx

    base = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000").rstrip("/")
    try:
        r = httpx.get(f"{base}/health", timeout=20.0)
        return r.status_code == 200 and (r.json() or {}).get("ollama") is True
    except Exception:
        return False


def _item_path_str(item) -> str:
    p = getattr(item, "path", None) or getattr(item, "fspath", None)
    return str(p) if p else ""


def pytest_collection_modifyitems(config, items):
    """When BOLA_AI_SKIP_LIVE_E2E=1, skip live E2E files (emergency CI only)."""
    if os.environ.get("BOLA_AI_SKIP_LIVE_E2E", "").lower() not in ("1", "true", "yes"):
        return
    skip = pytest.mark.skip(reason="BOLA_AI_SKIP_LIVE_E2E=1 (not default; live E2E is mandatory normally)")
    for item in items:
        if any(f in _item_path_str(item) for f in _LIVE_E2E_FILES):
            item.add_marker(skip)


def pytest_collection_finish(session):
    """Fail fast if live E2E tests are selected but the stack is not up."""
    if os.environ.get("BOLA_AI_SKIP_LIVE_E2E", "").lower() in ("1", "true", "yes"):
        return
    base = os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000").rstrip("/")
    for item in session.items:
        name = _item_path_str(item)
        if not any(f in name for f in _LIVE_E2E_FILES):
            continue
        if not _live_stack_reachable():
            pytest.exit(
                f"\n\n*** LIVE E2E REQUIRED ***\n"
                f"Selected tests require a running API + Ollama at {base}.\n"
                f"Start: cd docker && docker compose up -d\n"
                f"Then: PYTHONPATH=src python -m bola_ai.cli health --wait\n"
                f"Run full suite: PYTHONPATH=src pytest tests/ -v\n\n"
                f"Emergency only (CI without GPU): BOLA_AI_SKIP_LIVE_E2E=1 pytest ...\n",
                returncode=1,
            )
        break
