"""Chunk documentation for embedding and retrieval."""

import re
from typing import Iterator

# Approximate tokens per chunk (MiniLM uses ~256 subwords for short sentences)
CHUNK_SIZE = 512
CHUNK_OVERLAP = 64


def chunk_text(
    text: str,
    *,
    chunk_size: int = CHUNK_SIZE,
    overlap: int = CHUNK_OVERLAP,
) -> list[str]:
    """Split text into overlapping chunks (by character count, roughly sentence-aware)."""
    if not text or not text.strip():
        return []
    text = text.strip()
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
