"""Fake embedder for tests and low-memory mode — no ML model load."""

import hashlib
from typing import List

# Match dimension of all-MiniLM-L6-v2 for ChromaDB compatibility
EMBED_DIM = 384


class FakeEmbedder:
    """Deterministic embeddings; no model load."""

    def __init__(self, dim: int = EMBED_DIM):
        self._dim = dim

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        return [self._vec(t) for t in texts]

    def embed_query(self, query: str) -> List[float]:
        return self._vec(query)

    def _vec(self, text: str) -> List[float]:
        h = hashlib.sha256(text.encode()).digest()
        n = min(len(h), self._dim)
        out = [(b / 255.0 - 0.5) * 2 for b in h[:n]]
        out.extend([0.0] * (self._dim - len(out)))
        return out[: self._dim]
