"""Tests for CLI (invoke with --api to mock server or use TestClient)."""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_cli_health_fails_without_server():
    # Without API running, health should fail (connection error)
    env = {"PYTHONPATH": str(REPO_ROOT / "src")}
    r = subprocess.run(
        [sys.executable, "-m", "bola_ai.cli", "health", "--api", "http://127.0.0.1:19999"],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env={**__import__("os").environ, **env},
    )
    assert r.returncode != 0
