"""Chunk documentation for embedding and retrieval."""

import json
import re
from typing import Iterator

# Approximate tokens per chunk (MiniLM uses ~256 subwords for short sentences)
CHUNK_SIZE = 512
CHUNK_OVERLAP = 64


def _preprocess_har(text: str) -> str:
    """Convert HAR JSON into human-readable API summary for better chunking and embedding."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ""
    entries = data.get("log", {}).get("entries", [])
    if not entries:
        return ""

    lines: list[str] = ["# HAR API Capture Analysis\n"]
    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        method = req.get("method", "?")
        url = req.get("url", "?")
        status = resp.get("status", "?")

        lines.append(f"## {method} {url}")
        lines.append(f"Status: {status}")

        headers = {h["name"].lower(): h["value"] for h in req.get("headers", []) if "name" in h and "value" in h}
        if "authorization" in headers:
            lines.append(f"Authorization: {headers['authorization'][:80]}...")
        if "content-type" in headers:
            lines.append(f"Content-Type: {headers['content-type']}")

        post_data = req.get("postData", {})
        body_text = post_data.get("text", "")
        if body_text:
            # For GraphQL, extract the query
            try:
                body_json = json.loads(body_text)
                if "query" in body_json:
                    lines.append(f"GraphQL query: {body_json['query'][:500]}")
                if "variables" in body_json:
                    lines.append(f"Variables: {json.dumps(body_json['variables'])[:300]}")
                if "action" in str(body_json) or "message" in str(body_json):
                    lines.append(f"Request body: {body_text[:500]}")
            except (json.JSONDecodeError, ValueError):
                lines.append(f"Request body: {body_text[:500]}")

        resp_content = resp.get("content", {})
        resp_text = resp_content.get("text", "")
        if resp_text and len(resp_text) < 2000:
            try:
                resp_json = json.loads(resp_text)
                lines.append(f"Response: {json.dumps(resp_json, indent=2)[:800]}")
            except (json.JSONDecodeError, ValueError):
                lines.append(f"Response: {resp_text[:500]}")

        lines.append("")

    return "\n".join(lines)


def chunk_text(
    text: str,
    *,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    """Split text into overlapping chunks (by character count, roughly sentence-aware).

    Automatically detects and preprocesses HAR JSON files into a
    human-readable API summary before chunking.
    """
    if not text or not text.strip():
        return []
    text = text.strip()

    # Detect and preprocess HAR JSON
    if text.lstrip().startswith("{") and '"log"' in text[:200]:
        har_text = _preprocess_har(text)
        if har_text:
            text = har_text
    # Prefer splitting on newlines/paragraphs, then on sentence boundaries
    parts = re.split(r"\n\s*\n", text)
    chunks: list[str] = []
    buffer = ""

    for part in parts:
        part = part.strip()
        if not part:
            continue
        if len(buffer) + len(part) + 2 <= chunk_size:
            buffer = f"{buffer}\n\n{part}".strip() if buffer else part
            continue
        # Flush buffer if adding this part would exceed size
        if buffer:
            # Try to split buffer by sentences if it's still long
            for sub in _split_sentences(buffer, chunk_size, overlap):
                chunks.append(sub)
            buffer = ""
        # Start new buffer; if part is huge, split it too
        for sub in _split_sentences(part, chunk_size, overlap):
            chunks.append(sub)

    if buffer:
        for sub in _split_sentences(buffer, chunk_size, overlap):
            chunks.append(sub)

    return [c for c in chunks if c.strip()]


def _split_sentences(
    block: str, chunk_size: int, overlap: int
) -> Iterator[str]:
    """Split a block into chunks by size with overlap, trying to break at sentence boundaries."""
    if len(block) <= chunk_size:
        yield block
        return
    start = 0
    while start < len(block):
        end = min(start + chunk_size, len(block))
        slice_text = block[start:end]
        if end < len(block):
            last_dot = max(
                slice_text.rfind(". "),
                slice_text.rfind(".\n"),
                slice_text.rfind("? "),
                slice_text.rfind("! "),
            )
            if last_dot > chunk_size // 2:
                end = start + last_dot + 1
                slice_text = block[start:end]
        yield slice_text.strip()
        if end >= len(block):
            break
        new_start = end - overlap
        if new_start <= start:
            new_start = start + 1
        start = new_start
