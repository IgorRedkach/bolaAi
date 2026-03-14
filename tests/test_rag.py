"""Tests for RAG: chunking, store, embeddings."""
import pytest
from bola_ai.rag.chunking import chunk_text
from bola_ai.rag.store import DocStore


def test_chunk_text_empty():
    assert chunk_text("") == []
    assert chunk_text("   ") == []


def test_chunk_text_small():
    text = "One short paragraph."
    out = chunk_text(text)
    assert len(out) == 1
    assert "One short paragraph" in out[0]


def test_chunk_text_large():
    text = "A. " * 200  # many sentences
    out = chunk_text(text, chunk_size=100, overlap=10)
    assert len(out) >= 2
    assert all(len(c) <= 120 for c in out)


def test_store_add_and_search(store):
    store.add_document("GET /api/patients/{id} returns patient. No ownership check documented.", source="test")
    results = store.search("patient API authorization", n_results=5)
    assert len(results) >= 1
    assert "patient" in results[0]["content"].lower()


def test_store_count(store):
    assert store.count() == 0
    store.add_document("First doc.", source="a")
    assert store.count() >= 1
    store.add_document("Second doc.", source="b")
    assert store.count() >= 2
