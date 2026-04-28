"""
Load BOLA knowledge patterns into the RAG store.

Loads ONLY canonical knowledge files from data/knowledge/*.md:
  - bola_patterns.md
  - ai_teacher_bola_quality_patterns.md
  - phase1_small_model_guidelines.md

Training examples (data/training/*.jsonl, bola_rag_chunks.txt) are intentionally
excluded from the RAG store to prevent training-inference overlap: the model
must reason from retrieved evidence, not pattern-match against memorised examples.

Use with: python -m training.load_knowledge (from repo root).
"""

import os
import sys
from pathlib import Path

# Add src to path when run as script
repo_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(repo_root / "src"))

from bola_ai.config import CHROMA_PATH, COLLECTION_NAME, EMBEDDING_MODEL, USE_FAKE_EMBEDDER
from bola_ai.logging_config import setup_logging, get_logger
from bola_ai.rag.store import DocStore
from bola_ai.rag.fake_embedder import FakeEmbedder

setup_logging()
logger = get_logger("training.load_knowledge")


def main():
    logger.info("Loading BOLA knowledge into RAG store at %s", CHROMA_PATH)
    use_fake = USE_FAKE_EMBEDDER
    reset_before_load = True
    env_reset = str(os.environ.get("BOLA_AI_RESET_BEFORE_LOAD", "1")).lower()
    if env_reset in ("0", "false", "no"):
        reset_before_load = False

    kwargs = {
        "persist_directory": CHROMA_PATH,
        "collection_name": COLLECTION_NAME,
    }
    if use_fake:
        kwargs["embedder"] = FakeEmbedder()
        logger.info("Using fake embedder for knowledge load")
    else:
        kwargs["embedding_model"] = EMBEDDING_MODEL

    store = DocStore(
        **kwargs,
    )

    if reset_before_load:
        logger.info("Resetting collection before knowledge load")
        store.reset()

    knowledge_dir = repo_root / "data" / "knowledge"

    loaded = 0

    if knowledge_dir.exists():
        for f in sorted(knowledge_dir.glob("*.md")):
            logger.info("Loading knowledge file: %s", f.name)
            text = f.read_text(encoding="utf-8")
            store.add_document(text, source=f.name)
            loaded += 1
    else:
        logger.warning("Knowledge dir not found: %s", knowledge_dir)

    n = store.count()
    logger.info("Loaded %s knowledge file(s) into RAG. Total chunks: %s", loaded, n)
    print(f"Loaded {loaded} knowledge file(s) into RAG. Total chunks: {n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
