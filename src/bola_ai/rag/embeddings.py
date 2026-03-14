"""Local embedding model for RAG (offline)."""

from typing import List

from sentence_transformers import SentenceTransformer


class LocalEmbedder:
    """Thin wrapper around sentence-transformers for local embeddings."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._model = SentenceTransformer(model_name)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        embeddings = self._model.encode(texts, convert_to_numpy=True)
        return embeddings.tolist()

    def embed_query(self, query: str) -> List[float]:
        emb = self._model.encode([query], convert_to_numpy=True)
        return emb[0].tolist()
