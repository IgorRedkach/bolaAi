"""CLI: run BOLA AI security analysis via terminal and API."""

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

from bola_ai import config

API_BASE = "http://localhost:8000"
DEFAULT_TIMEOUT = 120.0


def _url(path: str, base: str = API_BASE) -> str:
    return f"{base.rstrip('/')}{path}"


def cmd_health(base: str, *, wait: bool) -> int:
    """Single check, or --wait until Ollama is up (stack startup; not LLM inference)."""
    if not wait:
        try:
            r = httpx.get(_url("/health", base), timeout=30.0)
            if not r.is_success:
                print(r.text, file=sys.stderr)
                return 1
            data = r.json() or {}
            print(json.dumps(data, indent=2))
            return 0 if data.get("ollama") else 1
        except Exception as e:
            print(f"Health check failed: {e}", file=sys.stderr)
            return 1

    deadline = time.monotonic() + config.STACK_READY_WAIT_SECONDS
    interval = 5.0
    first = True
    while True:
        try:
            r = httpx.get(_url("/health", base), timeout=30.0)
            if r.is_success:
                data = r.json() or {}
                if data.get("ollama"):
                    print(json.dumps(data, indent=2))
                    return 0
        except Exception:
            pass
        if time.monotonic() >= deadline:
            print(
                f"Timeout: API or Ollama not ready after {config.STACK_READY_WAIT_SECONDS}s "
                "(set BOLA_AI_STACK_WAIT_SECONDS for longer startup/training wait).",
                file=sys.stderr,
            )
            return 1
        if first:
            print(
                f"Waiting for stack (up to {int(config.STACK_READY_WAIT_SECONDS)}s, "
                f"{interval}s interval)...",
                file=sys.stderr,
            )
            first = False
        time.sleep(interval)


def cmd_ingest(content: str | None, file: Path | None, source: str, base: str) -> int:
    if file:
        text = file.read_text(encoding="utf-8")
        payload = {"content": text, "source": source or file.name}
    elif content:
        payload = {"content": content, "source": source or "cli"}
    else:
        print("Error: provide --content or --file", file=sys.stderr)
        return 1
    with httpx.Client(timeout=config.INGEST_HTTP_TIMEOUT) as client:
        r = client.post(_url("/ingest"), data=payload)  # form data
    if not r.is_success:
        print(r.text, file=sys.stderr)
        return 1
    print(r.json().get("message", r.text))
    return 0


def cmd_ingest_shared(relative_path: str, source: str, base: str) -> int:
    if not relative_path:
        print("Error: provide --relative-path", file=sys.stderr)
        return 1
    payload = {"relative_path": relative_path, "source": source or "shared_volume"}
    with httpx.Client(timeout=config.INGEST_HTTP_TIMEOUT) as client:
        r = client.post(_url("/ingest_shared", base), data=payload)
    if not r.is_success:
        print(r.text, file=sys.stderr)
        return 1
    print(r.json().get("message", r.text))
    return 0


def cmd_analyze(query: str | None, base: str) -> int:
    body = {"query": query} if query else None
    with httpx.Client(timeout=config.ANALYZE_CLIENT_TIMEOUT) as client:
        r = client.post(_url("/analyze"), json=body or {})
    if not r.is_success:
        print(r.text, file=sys.stderr)
        return 1
    data = r.json()
    report = data.get("report", "")
    print(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BOLA AI — local security analysis (API client)")
    parser.add_argument("--api", default=API_BASE, help="API base URL")
    sub = parser.add_subparsers(dest="command", required=True)

    hp = sub.add_parser("health", help="Health check (use --wait for stack startup until Ollama ready)")
    hp.add_argument(
        "--wait",
        action="store_true",
        help="Poll until Ollama is ready (BOLA_AI_STACK_WAIT_SECONDS; for Docker/training start, not LLM reply)",
    )

    ing = sub.add_parser("ingest", help="Ingest documentation")
    ing.add_argument("--content", "-c", help="Raw text to ingest")
    ing.add_argument("--file", "-f", type=Path, help="File path to ingest")
    ing.add_argument("--source", "-s", default="cli", help="Source label")

    ing_shared = sub.add_parser("ingest-shared", help="Ingest file from shared Docker docs volume")
    ing_shared.add_argument("--relative-path", "-r", required=True, help="Relative path under shared docs dir")
    ing_shared.add_argument("--source", "-s", default="shared_volume", help="Source label")

    ana = sub.add_parser("analyze", help="Run security analysis")
    ana.add_argument("--query", "-q", help="Custom analysis query")

    args = parser.parse_args()
    base = args.api

    if args.command == "health":
        return cmd_health(base, wait=getattr(args, "wait", False))
    if args.command == "ingest":
        return cmd_ingest(getattr(args, "content", None), getattr(args, "file", None), getattr(args, "source", "cli"), base)
    if args.command == "ingest-shared":
        return cmd_ingest_shared(getattr(args, "relative_path", ""), getattr(args, "source", "shared_volume"), base)
    if args.command == "analyze":
        return cmd_analyze(getattr(args, "query", None), base)
    return 1


if __name__ == "__main__":
    sys.exit(main())
