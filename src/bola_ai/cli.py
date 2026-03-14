"""CLI: run BOLA AI via terminal and API."""

import argparse
import json
import sys
from pathlib import Path

import httpx


API_BASE = "http://localhost:8000"
DEFAULT_TIMEOUT = 120.0


def _url(path: str, base: str = API_BASE) -> str:
    return f"{base.rstrip('/')}{path}"


def cmd_health(base: str) -> int:
    r = httpx.get(_url("/health", base), timeout=10.0)
    print(json.dumps(r.json(), indent=2))
    return 0 if r.is_success else 1


def cmd_ingest(content: str | None, file: Path | None, source: str, base: str) -> int:
    if file:
        text = file.read_text(encoding="utf-8")
        payload = {"content": text, "source": source or file.name}
    elif content:
        payload = {"content": content, "source": source or "cli"}
    else:
        print("Error: provide --content or --file", file=sys.stderr)
        return 1
    with httpx.Client(timeout=30.0) as client:
        r = client.post(_url("/ingest"), data=payload)  # form data
    if not r.is_success:
        print(r.text, file=sys.stderr)
        return 1
    print(r.json().get("message", r.text))
    return 0


def cmd_analyze(query: str | None, base: str) -> int:
    body = {"query": query} if query else None
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as client:
        r = client.post(_url("/analyze"), json=body or {})
    if not r.is_success:
        print(r.text, file=sys.stderr)
        return 1
    data = r.json()
    report = data.get("report", "")
    print(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="BOLA AI — local BOLA analysis (API client)")
    parser.add_argument("--api", default=API_BASE, help="API base URL")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="Health check")

    ing = sub.add_parser("ingest", help="Ingest documentation")
    ing.add_argument("--content", "-c", help="Raw text to ingest")
    ing.add_argument("--file", "-f", type=Path, help="File path to ingest")
    ing.add_argument("--source", "-s", default="cli", help="Source label")

    ana = sub.add_parser("analyze", help="Run BOLA analysis")
    ana.add_argument("--query", "-q", help="Custom analysis query")

    args = parser.parse_args()
    base = args.api

    if args.command == "health":
        return cmd_health(base)
    if args.command == "ingest":
        return cmd_ingest(getattr(args, "content", None), getattr(args, "file", None), getattr(args, "source", "cli"), base)
    if args.command == "analyze":
        return cmd_analyze(getattr(args, "query", None), base)
    return 1


if __name__ == "__main__":
    sys.exit(main())
