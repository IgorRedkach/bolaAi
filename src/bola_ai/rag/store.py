"""ChromaDB document store for RAG. ChromaDB is imported lazily in __init__ to avoid multi-GB load until a store is used."""

import uuid
from pathlib import Path
from typing import Any, Optional, Union

from bola_ai.config import CHROMA_PATH, COLLECTION_NAME, EMBEDDING_MODEL
from bola_ai.logging_config import get_logger
from bola_ai.rag.chunking import chunk_text
from bola_ai.rag.fake_embedder import FakeEmbedder

logger = get_logger("rag.store")

CHROMA_MAX_BATCH = 5000

# LocalEmbedder imported lazily to avoid loading sentence_transformers in tests


class DocStore:
    """Persistent document store with embeddings for RAG."""

    def __init__(
        self,
        persist_directory: Optional[Path] = None,
        collection_name: str = COLLECTION_NAME,
        embedding_model: str = EMBEDDING_MODEL,
        embedder: Optional[FakeEmbedder] = None,
    ):
        self.persist_directory = Path(persist_directory or CHROMA_PATH)
        self.persist_directory.mkdir(parents=True, exist_ok=True)
        self.collection_name = collection_name
        if embedder is not None:
            self.embedder = embedder
            logger.info("DocStore: using provided embedder (fake)")
        else:
            logger.info("DocStore: loading embedder model=%s", embedding_model)
            from bola_ai.rag.embeddings import LocalEmbedder
            self.embedder = LocalEmbedder(embedding_model)
        import chromadb
        from chromadb.config import Settings
        self._client = chromadb.PersistentClient(
            path=str(self.persist_directory),
            settings=Settings(anonymized_telemetry=False),
        )
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )

    def add_document(
        self,
        content: str,
        *,
        source: str = "upload",
        doc_id: Optional[str] = None,
    ) -> list[str]:
        """Chunk content, embed, and add to store. Returns list of chunk ids."""
        chunks = chunk_text(content)
        if not chunks:
            logger.debug("add_document: no chunks from content len=%s", len(content or ""))
            return []
        logger.debug("add_document: source=%s chunks=%s", source, len(chunks))
        ids = [doc_id or str(uuid.uuid4()) for _ in chunks]
        # Chroma expects one id per doc; we use composite ids for chunks
        chunk_ids = [f"{ids[0]}_{i}" for i in range(len(chunks))]
        embeddings = self.embedder.embed_documents(chunks)
        metadatas = [{"source": source, "chunk_index": i} for i in range(len(chunks))]
        for start in range(0, len(chunks), CHROMA_MAX_BATCH):
            end = min(start + CHROMA_MAX_BATCH, len(chunks))
            self._collection.add(
                ids=chunk_ids[start:end],
                embeddings=embeddings[start:end],
                documents=chunks[start:end],
                metadatas=metadatas[start:end],
            )
            if end < len(chunks):
                logger.info("add_document: batch %d-%d of %d added", start, end, len(chunks))
        return chunk_ids

    def add_documents(
        self,
        items: list[dict[str, Any]],
        *,
        content_key: str = "content",
        source_key: str = "source",
    ) -> list[str]:
        """Add multiple documents. Each item is a dict with content and optional source."""
        all_ids: list[str] = []
        for item in items:
            content = item.get(content_key) or item.get("text", "")
            source = item.get(source_key, "batch")
            ids = self.add_document(content, source=source)
            all_ids.extend(ids)
        return all_ids

    def search(
        self,
        query: str,
        n_results: int = 10,
        source_filter: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        """Return top-n chunks with metadata and distances.

        Args:
            source_filter: if provided, only return chunks whose ``source``
                metadata is in this list (ChromaDB ``$in`` filter).
        """
        q_emb = self.embedder.embed_query(query)
        kwargs: dict[str, Any] = {
            "query_embeddings": [q_emb],
            "n_results": min(n_results, 50),
            "include": ["documents", "metadatas", "distances"],
        }
        if source_filter:
            kwargs["where"] = {"source": {"$in": source_filter}}
        result = self._collection.query(**kwargs)
        out = []
        docs = result["documents"][0] if result["documents"] else []
        metas = result["metadatas"][0] if result["metadatas"] else []
        dists = result["distances"][0] if result.get("distances") else []
        for i, doc in enumerate(docs):
            out.append({
                "content": doc,
                "metadata": metas[i] if i < len(metas) else {},
                "distance": dists[i] if i < len(dists) else None,
            })
        return out

    def count(self) -> int:
        """Return number of chunks in the collection."""
        return self._collection.count()

    def reset(self) -> None:
        """Delete and recreate the collection (for testing: clear store between test cases)."""
        self._client.delete_collection(self.collection_name)
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("Store reset: collection %s cleared", self.collection_name)
